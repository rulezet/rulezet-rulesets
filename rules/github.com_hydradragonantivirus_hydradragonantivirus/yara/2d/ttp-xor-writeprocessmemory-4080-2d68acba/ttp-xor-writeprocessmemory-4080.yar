rule TTP_XOR_WriteProcessMemory_4080 {
  strings:
    $key_4080 = { 17 f2 [2] 25 d0 [2] 23 e5 [2] 0d e5 [2] 32 f9 }

  condition:
    any of them
}