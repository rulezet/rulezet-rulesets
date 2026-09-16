rule sig_20160517_7582cc9b4d0d992581f96a160d0f7d68 {
  meta:
    description = "datamaliciousorder - file 20160517_7582cc9b4d0d992581f96a160d0f7d68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2284d4b63af475302ecf0a6b5bbd50ab7e579472a82d696e95a8e8fc0e830e56"

  strings:
    $s1 = "var tkeuk='vfz4w1azpwjlrbxzfh pguieeken4cwv2dwl3nglydbkaxiokxilir3jk3rxdkfbyjmafkqctvlnmjjg3ork=pawsm\\'yq1qhte2r4zcnlfpbndqq4ci" ascii
    $s2 = "v=r4+\"v\"+\"al\";   WScript.lister=5;   y2ispflrv=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+\"ng\"+\"th\"])  " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}