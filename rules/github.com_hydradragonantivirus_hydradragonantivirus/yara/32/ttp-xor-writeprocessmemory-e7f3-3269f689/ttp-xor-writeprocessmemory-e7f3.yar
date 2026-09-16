rule TTP_XOR_WriteProcessMemory_e7f3 {
  strings:
    $key_e7f3 = { b0 81 [2] 82 a3 [2] 84 96 [2] aa 96 [2] 95 8a }

  condition:
    any of them
}