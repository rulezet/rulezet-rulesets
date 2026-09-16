rule TTP_XOR_WriteProcessMemory_e762 {
  strings:
    $key_e762 = { b0 10 [2] 82 32 [2] 84 07 [2] aa 07 [2] 95 1b }

  condition:
    any of them
}