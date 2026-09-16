rule _20160921_52ab3697b827675e3be965f7171e236d_20160921_8644cb559dff_5178 {
  meta:
    description = "datamaliciousorder - from files 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js, 20160921_aab5fb25ea8971982ac223655d50aba2.js, 20160921_b1a0d856c15e8cb36e6ba699332db942.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash2       = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"
    hash3       = "0387ef653c0ac9c5d0aaf638bde80688e7b6b279a435dcab3ff679313abfab3c"
    hash4       = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"

  strings:
    $s1 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){retu" ascii
    $s2 = "unction fuck(){return \"XHj\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){re" ascii
    $s3 = "(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";" ascii
    $s4 = "(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck()" ascii
    $s5 = "r\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}