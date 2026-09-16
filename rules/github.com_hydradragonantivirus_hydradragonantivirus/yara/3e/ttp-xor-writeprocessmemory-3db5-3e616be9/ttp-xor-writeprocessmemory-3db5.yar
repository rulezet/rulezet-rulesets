rule TTP_XOR_WriteProcessMemory_3db5 {
  strings:
    $key_3db5 = { 6a c7 [2] 58 e5 [2] 5e d0 [2] 70 d0 [2] 4f cc }

  condition:
    any of them
}