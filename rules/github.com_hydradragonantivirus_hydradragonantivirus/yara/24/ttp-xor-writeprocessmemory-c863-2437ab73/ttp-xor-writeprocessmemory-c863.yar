rule TTP_XOR_WriteProcessMemory_c863 {
  strings:
    $key_c863 = { 9f 11 [2] ad 33 [2] ab 06 [2] 85 06 [2] ba 1a }

  condition:
    any of them
}