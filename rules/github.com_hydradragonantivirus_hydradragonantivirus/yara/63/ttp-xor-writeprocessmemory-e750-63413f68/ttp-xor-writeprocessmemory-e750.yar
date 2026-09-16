rule TTP_XOR_WriteProcessMemory_e750 {
  strings:
    $key_e750 = { b0 22 [2] 82 00 [2] 84 35 [2] aa 35 [2] 95 29 }

  condition:
    any of them
}