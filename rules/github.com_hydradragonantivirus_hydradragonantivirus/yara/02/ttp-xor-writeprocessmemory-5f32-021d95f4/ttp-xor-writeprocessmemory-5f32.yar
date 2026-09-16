rule TTP_XOR_WriteProcessMemory_5f32 {
  strings:
    $key_5f32 = { 08 40 [2] 3a 62 [2] 3c 57 [2] 12 57 [2] 2d 4b }

  condition:
    any of them
}