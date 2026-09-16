rule TTP_XOR_WriteProcessMemory_58e6 {
  strings:
    $key_58e6 = { 0f 94 [2] 3d b6 [2] 3b 83 [2] 15 83 [2] 2a 9f }

  condition:
    any of them
}