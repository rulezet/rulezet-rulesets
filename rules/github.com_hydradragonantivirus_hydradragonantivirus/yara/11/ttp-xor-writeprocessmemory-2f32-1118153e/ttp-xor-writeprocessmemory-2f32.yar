rule TTP_XOR_WriteProcessMemory_2f32 {
  strings:
    $key_2f32 = { 78 40 [2] 4a 62 [2] 4c 57 [2] 62 57 [2] 5d 4b }

  condition:
    any of them
}