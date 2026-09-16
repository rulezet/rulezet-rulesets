rule TTP_XOR_WriteProcessMemory_4db5 {
  strings:
    $key_4db5 = { 1a c7 [2] 28 e5 [2] 2e d0 [2] 00 d0 [2] 3f cc }

  condition:
    any of them
}