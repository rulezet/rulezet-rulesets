rule TTP_XOR_WriteProcessMemory_22e2 {
  strings:
    $key_22e2 = { 75 90 [2] 47 b2 [2] 41 87 [2] 6f 87 [2] 50 9b }

  condition:
    any of them
}