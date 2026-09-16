rule TTP_XOR_WriteProcessMemory_c830 {
  strings:
    $key_c830 = { 9f 42 [2] ad 60 [2] ab 55 [2] 85 55 [2] ba 49 }

  condition:
    any of them
}