rule TTP_XOR_WriteProcessMemory_51e6 {
  strings:
    $key_51e6 = { 06 94 [2] 34 b6 [2] 32 83 [2] 1c 83 [2] 23 9f }

  condition:
    any of them
}