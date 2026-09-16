rule TTP_XOR_WriteProcessMemory_c843 {
  strings:
    $key_c843 = { 9f 31 [2] ad 13 [2] ab 26 [2] 85 26 [2] ba 3a }

  condition:
    any of them
}