rule infected_107_175_218_241_2018_10_14a_shells_dc3 {
  meta:
    description = "shells - file dc3.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-10-28"
    hash1       = "3ace35f15c854f5e0183a17a38b7e6cafa2553a10c9e3b3fc5f7c06c2ef0f81e"

  strings:
    $x1  = "(){if(empty($_POST[\"ch\"]))$_POST[\"ch\"]=$GLOBALS[\"default\\137charset\"];global $_vza;echo\"<\\150tml><head><met\\x61 http-" ascii
    $s2  = "();}function acTiOnLogout(){SetCoOkIe($GLOBALS[\"coo\\153\"],\"\",TiME()-(int)round(1800+1800));die(\"bye!\");}function _" fullword ascii
    $s3  = "='Content-\\124ype' conte\\156t='\\164ext/h\\x74ml; c\\150\\141rset=\".$_POST[\"\\x63h\"].\"'><t\\151tle>\".$_SERVER[\"HTTP_HOST" ascii
    $s4  = "($_POST[\"p\"]).\" <span>\\117wner\\x2fGroup:</span>\\x20\".$_mkds[\"name\"].\"/\".$_ltxp[\"n\\141me\"].\"<br>\";echo\"<span>Cha" ascii
    $s5  = "lEmtIMe($_POST[\"p\"])).\"\\x22\\076<in\\160ut type=submi\\164 value=\\042>>\\042></f\\157r\\155>\";break;}echo\"</div>\";_" fullword ascii
    $s6  = "();}function ActiOnFt(){if(isset($_POST[\"p\"]))$_POST[\"p\"]=StR_rOT13(uRLdeCODE($_POST[\"p\"]));if(isset($_POST[\"x\"])){switc" ascii
    $s7  = "($_xw[\"size\"]):$_xw[\"type\"]).\"<\\x2ftd><td>\".$_xw[\"modify\"].\"</td><td>\".$_xw[\"owner\"].\"/\".$_xw[\"gr\\x6fup\"].\"</" ascii
    $s8  = "s\"],\"po\\163ix\\x5fgetgrgid\")===false)){function PoSIx_gETgRGid($_hp){return false;}}function _" fullword ascii
    $s9  = "66666666666667" ascii  
    $s10 = "666666666667" ascii  
    $s11 = "6666666667" ascii  
    $s12 = "$ps=\"de9\\x31\\070f6ea2e947\\x39ed9d81a814\\067\\144bae3d\";$_vza=\"#df5\";$_smp=\"fm\";$default_charset=\"Windows-1\\06251\";i" ascii
    $s13 = "($_ioko){if(fUnCTIOn_ExiSts(\"scandi\\x72\")){return scAnDir($_ioko);}else{$_ip=opeNdIr($_ioko);while(false!==($_io=rEadDir($_ip" ascii
    $s14 = "ed\");else echo\"unlink error\\x21\";if($_POST[\"p\"]!=\"yes\")_" fullword ascii
    $s15 = "(FIlESizE($_POST[\"p\"])):\"-\").\"\\040<\\163\\160an>\\x50ermi\\163sion:<\\057span>\\040\"._" fullword ascii
    $s16 = "\\x2f\\x61\\x3e <span>Dat\\145ti\\x6de:</span> \".daTE(\"Y-m-d H:i:s\").\"<br\\x3e\".($_jl?_" fullword ascii
    $s17 = "($_xw);else @Unlink($_xw);}break;}if($_rdbd)ToUCh($_POST[\"c\"],$_rdbd,$_rdbd);}_" fullword ascii
    $s18 = "7=3 \\x63ellsp\\141cing=0 width=100%><tr>\".$_ubi.\"</tr><\\x2ft\\141ble><\\x64iv style=\\x22margin:5\\042>\";}function _" fullword ascii
    $s19 = "(isset($_POST[\"c\"])?$_POST[\"c\"]:$GLOBALS[\"c\\167d\"]);if($_zka===false){echo\"Can't \\157pen this\\040folder!\";_" fullword ascii
    $s20 = "d(0+0+0),-154+157);if(isset($_POST[\"ps\"])&&(md5($_POST[\"ps\"])==$ps))_" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 80KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}