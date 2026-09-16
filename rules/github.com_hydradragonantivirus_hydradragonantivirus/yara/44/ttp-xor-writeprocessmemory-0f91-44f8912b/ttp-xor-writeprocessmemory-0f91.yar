rule TTP_XOR_WriteProcessMemory_0f91 {
  strings:
    $key_0f91 = { 58 e3 [2] 6a c1 [2] 6c f4 [2] 42 f4 [2] 7d e8 }

  condition:
    any of them
}