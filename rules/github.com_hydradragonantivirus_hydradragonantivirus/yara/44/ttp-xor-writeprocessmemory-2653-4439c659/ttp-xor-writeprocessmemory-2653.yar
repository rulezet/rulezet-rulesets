rule TTP_XOR_WriteProcessMemory_2653 {
  strings:
    $key_2653 = { 71 21 [2] 43 03 [2] 45 36 [2] 6b 36 [2] 54 2a }

  condition:
    any of them
}