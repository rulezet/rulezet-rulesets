rule TTP_XOR_WriteProcessMemory_58c3 {
  strings:
    $key_58c3 = { 0f b1 [2] 3d 93 [2] 3b a6 [2] 15 a6 [2] 2a ba }

  condition:
    any of them
}