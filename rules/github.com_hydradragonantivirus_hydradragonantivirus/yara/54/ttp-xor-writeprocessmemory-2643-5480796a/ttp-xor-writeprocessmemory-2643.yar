rule TTP_XOR_WriteProcessMemory_2643 {
  strings:
    $key_2643 = { 71 31 [2] 43 13 [2] 45 26 [2] 6b 26 [2] 54 3a }

  condition:
    any of them
}