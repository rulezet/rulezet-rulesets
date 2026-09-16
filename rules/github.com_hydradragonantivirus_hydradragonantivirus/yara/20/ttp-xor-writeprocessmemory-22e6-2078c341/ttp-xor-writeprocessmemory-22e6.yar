rule TTP_XOR_WriteProcessMemory_22e6 {
  strings:
    $key_22e6 = { 75 94 [2] 47 b6 [2] 41 83 [2] 6f 83 [2] 50 9f }

  condition:
    any of them
}