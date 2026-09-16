rule TTP_XOR_WriteProcessMemory_e707 {
  strings:
    $key_e707 = { b0 75 [2] 82 57 [2] 84 62 [2] aa 62 [2] 95 7e }

  condition:
    any of them
}