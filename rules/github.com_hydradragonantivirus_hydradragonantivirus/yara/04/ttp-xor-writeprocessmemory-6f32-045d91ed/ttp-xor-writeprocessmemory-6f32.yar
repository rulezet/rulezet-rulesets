rule TTP_XOR_WriteProcessMemory_6f32 {
  strings:
    $key_6f32 = { 38 40 [2] 0a 62 [2] 0c 57 [2] 22 57 [2] 1d 4b }

  condition:
    any of them
}