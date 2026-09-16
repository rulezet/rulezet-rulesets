rule _20160921_19d073f9fafc88c8b86047e72c80e9d8_20160921_4855f7b1e1da_3452 {
  meta:
    description = "datamaliciousorder - from files 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_4855f7b1e1da9c1c5863fa798f27645a.js, 20160921_6ca29d2ebdcaa2724b801c02414faf7f.js, 20160921_a56de0614f7815cff3fcb9f56233dbb4.js, 20160921_fa11dbc1cb358c8446ac1ba033c8a4c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash2       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"
    hash3       = "b810435d98ebab77ad9d2cd316e2a0c0211b0941d86cbfa6c0e753732c6d3b15"
    hash4       = "fa71b33b4ef1bf0fefff91c2876915e8ca80c82d473862703c383c6da0ad0186"
    hash5       = "27a60061641d8c44f2b882fcd06e72ca5721eaecb40ea10ad0b87c0c5f3c236f"

  strings:
    $s1 = "eturn \"TKp\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"TKp\";})()" ascii
    $s2 = "nction f000(){return \"YTp\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(function f000(){retu" ascii
    $s3 = "on f000(){return \"Wy\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"" ascii
    $s4 = "0(){return \"NBs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKp\";" ascii
    $s5 = "rn \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(func" ascii
    $s6 = "\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"DYx\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}