rule TTP_XOR_WriteProcessMemory_5862 {
  strings:
    $key_5862 = { 0f 10 [2] 3d 32 [2] 3b 07 [2] 15 07 [2] 2a 1b }

  condition:
    any of them
}