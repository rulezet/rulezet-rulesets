rule _20160921_1766f5c818d6371cb36488c98158ccd2_20160921_90c3374aed1b_4503 {
  meta:
    description = "datamaliciousorder - from files 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_90c3374aed1b4618a92eb40cb007c4b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash2       = "42b3d35e818b5b373b42427cc936c0a099078535d6f37eb5d4dc22b8ac1ee151"

  strings:
    $s1 = "{return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TRc\";})(" ascii
    $s2 = "n f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"" ascii
    $s3 = "})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"XTn\";})(),(function f00" ascii
    $s4 = "0(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Nx\";}" ascii
    $s5 = "eturn \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"IPu\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}