rule TTP_XOR_WriteProcessMemory_ea07 {
  strings:
    $key_ea07 = { bd 75 [2] 8f 57 [2] 89 62 [2] a7 62 [2] 98 7e }

  condition:
    any of them
}