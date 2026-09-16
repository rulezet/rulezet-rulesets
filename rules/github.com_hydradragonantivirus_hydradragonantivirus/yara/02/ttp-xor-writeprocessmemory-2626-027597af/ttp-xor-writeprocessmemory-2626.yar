rule TTP_XOR_WriteProcessMemory_2626 {
  strings:
    $key_2626 = { 71 54 [2] 43 76 [2] 45 43 [2] 6b 43 [2] 54 5f }

  condition:
    any of them
}