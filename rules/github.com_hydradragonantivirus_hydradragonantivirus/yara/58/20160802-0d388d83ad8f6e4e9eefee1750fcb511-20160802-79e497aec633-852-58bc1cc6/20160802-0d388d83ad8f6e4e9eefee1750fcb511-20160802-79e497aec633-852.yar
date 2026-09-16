rule _20160802_0d388d83ad8f6e4e9eefee1750fcb511_20160802_79e497aec633_852 {
  meta:
    description = "datamaliciousorder - from files 20160802_0d388d83ad8f6e4e9eefee1750fcb511.js, 20160802_79e497aec6332bd78066ff3c85d09928.js, 20160802_e226eacc6704b1f6be0f59e1568ab0a8.js, 20160802_f5051df17290dd506a2f09ad4e25421d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5565dfa0700774059944c32b2529989859e6f876e55bda27c573aaef31eaa10"
    hash2       = "d954a874b42508825156f3308124a6538570ab0bbee6cffa658984533df7ebe9"
    hash3       = "0d1c526845cd2bc23f3b762488491ee0346afd217faeefea315e0c733bfeff9c"
    hash4       = "1b79d5ffb0180282eaf5eabc40131f7fa5362ad12f874827eb9eeb91b136de4b"

  strings:
    $s1 = "\"\";\\r\\nfunction ORk1(Ds){return\\x20Ds;};\\x76ar Xz4 = \"se\"\\x20+ \"\";\\r\\nvar Pg3\\x20= \"clo\" + \"\";\\r\\nf\\x75ncti" ascii
    $s2 = "r WXb =\\x20\"en\" + \"\";\\r\\nvar \\x43b2 = \"o\\x70\" +\\x20\"\"\\x3b\\r\\nfunc\\x74i\\x6fn Hf8(FMs){return FMs;}\\x3bvar Jz1" ascii
    $s3 = " \"eT\" + \"\";\\r\\nvar Fy = \"Sav\" + \"\";\\r\\nfu\\x6ection Nq(O\\x42j){return O\\x42j;\\x7d;functi\\x6fn\\x20ETx9(ZZc8){ret" ascii
    $s4 = "72){return L\\x72;\\x7d;fu\\x6ection \\x58p6\\x28I\\x6b){return Ik;};var Fu3 =\\x20\"O\" + \"\";\\r\\nfunction Vw3\\x28NAa){retu" ascii
    $s5 = " Er8;};functio\\x6e RV\\x79(Mb0){return Mb0;};v\\x61r\\x20Z\\x56t7\\x20= \"le\\x22 + \"\\x22;\\r\\nvar LWr\\x20= \"oFi\" + \"\";" ascii

  condition:
    (uint16(0) == 0x200a and (all of them)
    ) or (all of them)
}