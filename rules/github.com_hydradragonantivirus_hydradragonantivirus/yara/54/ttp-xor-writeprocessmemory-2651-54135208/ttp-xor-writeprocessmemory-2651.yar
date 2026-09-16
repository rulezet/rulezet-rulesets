rule TTP_XOR_WriteProcessMemory_2651 {
  strings:
    $key_2651 = { 71 23 [2] 43 01 [2] 45 34 [2] 6b 34 [2] 54 28 }

  condition:
    any of them
}