rule _20160921_0298568f245d937dde081d505d360a5e_20160921_21041f3360c4_4132 {
  meta:
    description = "datamaliciousorder - from files 20160921_0298568f245d937dde081d505d360a5e.js, 20160921_21041f3360c455bf09d8b48dda6959f3.js, 20160921_469953d9833167e141d9f086f1f41437.js, 20160921_c01f87df9de4ce5ca88bd5f8e99b8421.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f31455e0194491e66143329dadae1760f33af4219844671541520909cf32d58"
    hash2       = "de559d9fde4fb08962605e84afb3f8e86d21c757f1189b673ed0648e3dd75cd0"
    hash3       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"
    hash4       = "863f188b1216c3a7a1dc561983400a4e8b6fadded702cf47ee8533061495abc8"

  strings:
    $s1 = "(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Py\";})(),(function fuck()" ascii
    $s2 = "eturn \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Np\";})()," ascii
    $s3 = "g\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Py\";})(),(function " ascii
    $s4 = "n \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Xw\";})(),(func" ascii
    $s5 = "ction fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}