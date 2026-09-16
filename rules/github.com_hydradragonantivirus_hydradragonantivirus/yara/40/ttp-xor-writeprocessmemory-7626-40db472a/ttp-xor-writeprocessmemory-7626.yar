rule TTP_XOR_WriteProcessMemory_7626 {
  strings:
    $key_7626 = { 21 54 [2] 13 76 [2] 15 43 [2] 3b 43 [2] 04 5f }

  condition:
    any of them
}