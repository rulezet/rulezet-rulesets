rule TTP_XOR_WriteProcessMemory_e761 {
  strings:
    $key_e761 = { b0 13 [2] 82 31 [2] 84 04 [2] aa 04 [2] 95 18 }

  condition:
    any of them
}