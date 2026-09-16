rule sig_20160824_6b0f88a76832e1fd5a1555eff7e7f704 {
  meta:
    description = "datamaliciousorder - file 20160824_6b0f88a76832e1fd5a1555eff7e7f704.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bb834ff8b1eaf7b24ab6350908649a238daf467e96b1a31f6bce01364bc789c"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}