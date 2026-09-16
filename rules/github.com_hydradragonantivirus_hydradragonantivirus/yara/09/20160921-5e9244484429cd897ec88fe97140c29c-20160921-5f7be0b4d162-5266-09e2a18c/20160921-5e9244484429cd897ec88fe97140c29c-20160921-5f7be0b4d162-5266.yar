rule _20160921_5e9244484429cd897ec88fe97140c29c_20160921_5f7be0b4d162_5266 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e9244484429cd897ec88fe97140c29c.js, 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_62f4f68c59540f36d255485f0f0e37c9.js, 20160921_69a85efe2b4b34254269f0f82213bf2c.js, 20160921_9b04118eed50c5e7331c4157a5c4dfc8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "002e6ee9d0d9e7f54ead7f8981f20be210819f7a75c52e3d1e91de2fd03ada17"
    hash2       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash3       = "4e9c7d3504791445d99c11b26a2aad12b3de66c6ef81ae8c7032e0310dda3d06"
    hash4       = "8def27dca1738a7df5978549903a2c809fcb8a8d158e5de122afc54ad2dd3dea"
    hash5       = "fdb29344d617d9ae88ae6d7109bec25567e1c486cbb28c248a65e9f2a678c75d"

  strings:
    $s1 = "){return \"UXf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";})" ascii
    $s2 = "function fuck(){return \"KVh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){r" ascii
    $s3 = "\"ZVi\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Mw\";})(),(functi" ascii
    $s4 = "tion fuck(){return \"Fv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii
    $s5 = "uck(){return \"Na\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UXf" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}