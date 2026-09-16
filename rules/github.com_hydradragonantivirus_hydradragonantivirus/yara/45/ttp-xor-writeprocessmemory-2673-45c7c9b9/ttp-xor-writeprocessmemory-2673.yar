rule TTP_XOR_WriteProcessMemory_2673 {
  strings:
    $key_2673 = { 71 01 [2] 43 23 [2] 45 16 [2] 6b 16 [2] 54 0a }

  condition:
    any of them
}