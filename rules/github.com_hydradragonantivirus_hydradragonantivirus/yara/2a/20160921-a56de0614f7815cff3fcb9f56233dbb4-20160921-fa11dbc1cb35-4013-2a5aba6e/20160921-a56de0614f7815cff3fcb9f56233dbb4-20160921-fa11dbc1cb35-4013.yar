rule _20160921_a56de0614f7815cff3fcb9f56233dbb4_20160921_fa11dbc1cb35_4013 {
  meta:
    description = "datamaliciousorder - from files 20160921_a56de0614f7815cff3fcb9f56233dbb4.js, 20160921_fa11dbc1cb358c8446ac1ba033c8a4c7.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa71b33b4ef1bf0fefff91c2876915e8ca80c82d473862703c383c6da0ad0186"
    hash2       = "27a60061641d8c44f2b882fcd06e72ca5721eaecb40ea10ad0b87c0c5f3c236f"
    hash3       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1 = "n f000(){return \"Br\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"B" ascii
    $s2 = "000(){return \"ZGq\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj" ascii
    $s3 = "000(){return \"Tn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s4 = " f000(){return \"MJq\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s5 = "function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){re" ascii
    $s6 = "{return \"Sq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}