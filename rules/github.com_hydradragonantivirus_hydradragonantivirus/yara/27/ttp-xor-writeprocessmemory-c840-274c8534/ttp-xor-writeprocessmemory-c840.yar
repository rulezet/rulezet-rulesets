rule TTP_XOR_WriteProcessMemory_c840 {
  strings:
    $key_c840 = { 9f 32 [2] ad 10 [2] ab 25 [2] 85 25 [2] ba 39 }

  condition:
    any of them
}