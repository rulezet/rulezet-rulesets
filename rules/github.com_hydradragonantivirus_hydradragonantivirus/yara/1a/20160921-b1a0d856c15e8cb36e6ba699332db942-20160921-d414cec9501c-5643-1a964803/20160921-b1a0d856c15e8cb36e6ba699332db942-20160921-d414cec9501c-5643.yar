rule _20160921_b1a0d856c15e8cb36e6ba699332db942_20160921_d414cec9501c_5643 {
  meta:
    description = "datamaliciousorder - from files 20160921_b1a0d856c15e8cb36e6ba699332db942.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"
    hash2       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"

  strings:
    $s1 = "(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){" ascii
    $s2 = "nction fuck(){return \"Py\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){retur" ascii
    $s3 = "k(){return \"IPu\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq" ascii
    $s4 = "urn \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(fun" ascii
    $s5 = "ction fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}