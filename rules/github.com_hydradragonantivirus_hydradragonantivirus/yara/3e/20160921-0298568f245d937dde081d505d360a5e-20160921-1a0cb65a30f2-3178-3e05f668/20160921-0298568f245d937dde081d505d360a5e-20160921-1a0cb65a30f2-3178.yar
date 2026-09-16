rule _20160921_0298568f245d937dde081d505d360a5e_20160921_1a0cb65a30f2_3178 {
  meta:
    description = "datamaliciousorder - from files 20160921_0298568f245d937dde081d505d360a5e.js, 20160921_1a0cb65a30f2e052b2abb4edb6b853f4.js, 20160921_21041f3360c455bf09d8b48dda6959f3.js, 20160921_4bd4835c5d72bd0171c38863a7d5fba6.js, 20160921_82c6439487239a08e403c18f347e12e6.js, 20160921_a8c002f684df9aec957f2a082ed80d84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f31455e0194491e66143329dadae1760f33af4219844671541520909cf32d58"
    hash2       = "cb576c42df90a554f241d4a5ba0dee1dfcb9caf661cf46a2800b743aa592e644"
    hash3       = "de559d9fde4fb08962605e84afb3f8e86d21c757f1189b673ed0648e3dd75cd0"
    hash4       = "34fcd9c1543d39dfd57d9c09da7c6123934388bbc0bf645db2a4dae174f514cc"
    hash5       = "db301ab72cd18ad4198865983d8e64e1840325c04d40cacaa8f5e2097faee094"
    hash6       = "9db5f5694048d441a47fe4382700213cc288d4fba152eec7b99fdd310a50ef7d"

  strings:
    $s1 = "){return \"Fv\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})()" ascii
    $s2 = "XHj\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Za\";})(),(functio" ascii
    $s3 = "on fuck(){return \"QTc\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return " ascii
    $s4 = "(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){re" ascii
    $s5 = "function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){retu" ascii
    $s6 = "e\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}