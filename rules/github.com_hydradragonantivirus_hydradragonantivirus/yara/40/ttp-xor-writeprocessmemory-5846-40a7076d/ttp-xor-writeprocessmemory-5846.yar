rule TTP_XOR_WriteProcessMemory_5846 {
  strings:
    $key_5846 = { 0f 34 [2] 3d 16 [2] 3b 23 [2] 15 23 [2] 2a 3f }

  condition:
    any of them
}