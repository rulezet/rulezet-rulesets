rule sig_20160517_ecd0a7bdb85a617053ecf4a00d63db30 {
  meta:
    description = "datamaliciousorder - file 20160517_ecd0a7bdb85a617053ecf4a00d63db30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc7e9369269c10267e10dad1c81b900b6c1a9998bf40674e3670524a4ba589ae"

  strings:
    $s1 = "var gk2v='vmhnogagpfgxrobbvt bxc3ksypamtrnlauqzlk344mrnssyqx14vvjhit4kaybairyyhd3b=unq1q\\'gjembtbcbh3czekuini4o4mid2yn4fklrumud" ascii
    $s2 = "Script.lister=5;   vi3gzxngsa=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+\"ng\"+\"th\"])  {      kj1stl11dx=287" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}