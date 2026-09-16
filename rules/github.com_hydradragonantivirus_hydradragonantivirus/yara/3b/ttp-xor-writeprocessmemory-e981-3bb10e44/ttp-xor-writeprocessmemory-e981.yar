rule TTP_XOR_WriteProcessMemory_e981 {
  strings:
    $key_e981 = { be f3 [2] 8c d1 [2] 8a e4 [2] a4 e4 [2] 9b f8 }

  condition:
    any of them
}