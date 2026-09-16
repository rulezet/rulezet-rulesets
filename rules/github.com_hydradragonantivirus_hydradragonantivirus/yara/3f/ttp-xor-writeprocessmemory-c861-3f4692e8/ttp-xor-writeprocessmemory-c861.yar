rule TTP_XOR_WriteProcessMemory_c861 {
  strings:
    $key_c861 = { 9f 13 [2] ad 31 [2] ab 04 [2] 85 04 [2] ba 18 }

  condition:
    any of them
}