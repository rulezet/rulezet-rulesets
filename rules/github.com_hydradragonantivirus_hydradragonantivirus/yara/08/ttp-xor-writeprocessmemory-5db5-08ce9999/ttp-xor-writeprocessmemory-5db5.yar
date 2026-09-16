rule TTP_XOR_WriteProcessMemory_5db5 {
  strings:
    $key_5db5 = { 0a c7 [2] 38 e5 [2] 3e d0 [2] 10 d0 [2] 2f cc }

  condition:
    any of them
}