rule sig_20160517_8d2bb16d930a91fcdb5d9b309e3e87d2 {
  meta:
    description = "datamaliciousorder - file 20160517_8d2bb16d930a91fcdb5d9b309e3e87d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "674715cf7603817e1b2c749eb45b28700a6a9e4d67d28a7324c96edd56e92226"

  strings:
    $s1 = "var dhab4='vlvwndavfm1arxqqek e4vaequetwhahoy2vazeqbvziobloiugezoyaxro2fstgtqcenfpoztywwa2jvsyg=idqpd\\'fja22to2vmucaeivynb1xxxi" ascii
    $s2 = "+\"xp\");   swqryfvz=r4+\"v\"+\"al\";   WScript.lister=5;   swqryfvz=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}