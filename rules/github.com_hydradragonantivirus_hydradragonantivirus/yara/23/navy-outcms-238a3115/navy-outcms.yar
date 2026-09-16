rule Navy_outcms {
  meta:
    description = "Navy - file outcms.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2020-07-23"
    hash1       = "7363e4577f2485886f23054ec2eddad853f0b922490848e2baf72cb3be9f54fe"

  strings:
    $s1  = "$html = get_page($d['template_url']);" fullword ascii
    $s2  = "if(array_keys($_GET)[0] && array_keys($_GET)[0] == 'init' ){" fullword ascii
    $s3  = "$result['PostURL'] = $_SERVER['SCRIPT_URI'].$filename;" fullword ascii
    $s4  = "elseif(array_keys($_GET)[0] && array_keys($_GET)[0] == 'list'){" fullword ascii
    $s5  = "$result['PostURL'] = str_replace(basename($_SERVER['SCRIPT_URI']),\"\", $result['PostURL']);" fullword ascii
    $s6  = "elseif(array_keys($_GET)[0] && array_keys($_GET)[0] !== 'init' && array_keys($_GET)[0] !== 'list'){" fullword ascii
    $s7  = "/* if(!$d['template_url'] || $d['template_url'] == \"\"){" fullword ascii
    $s8  = "$d = file_get_contents('php://input');" fullword ascii
    $s9  = "//posts exists and override set to 0 (No)" fullword ascii
    $s10 = "/* echo $script_path;" fullword ascii
    $s11 = "//$path = array(\"content/pages\", \"contents/pages\", \"contents/posts\", \"pages/content\",\"posts/content\");" fullword ascii
    $s12 = "echo ('{\"result\": \"Error. Post exists\",\"action\":\"Upload Post\" }');" fullword ascii
    $s13 = "if($_POST['ver'] && $_POST['ver'] == 'upd'){" fullword ascii
    $s14 = "if(a($filename,$posts) && $d['or'] == 0){" fullword ascii
    $s15 = "if($d == false && isset($_POST['a']) == false)" fullword ascii
    $s16 = "$result['result'] = \"Error. No Such Post\";" fullword ascii
    $s17 = "if($_POST['a'] && $_POST['a' ] == 'upl' ){" fullword ascii
    $s18 = "$result['action'] = \"Upload Post\";" fullword ascii
    $s19 = "$posts = scandir(getcwd());" fullword ascii
    $s20 = "$files = scandir(getcwd());" fullword ascii

  condition:
    uint16(0) == 0x3f3c and filesize < 10KB and
    8 of them
}