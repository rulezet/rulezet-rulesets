rule TTP_XOR_WriteProcessMemory_6db5 {
  strings:
    $key_6db5 = { 3a c7 [2] 08 e5 [2] 0e d0 [2] 20 d0 [2] 1f cc }

  condition:
    any of them
}