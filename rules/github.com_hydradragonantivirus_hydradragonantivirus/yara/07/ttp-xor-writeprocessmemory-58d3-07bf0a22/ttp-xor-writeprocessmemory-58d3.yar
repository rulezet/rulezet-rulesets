rule TTP_XOR_WriteProcessMemory_58d3 {
  strings:
    $key_58d3 = { 0f a1 [2] 3d 83 [2] 3b b6 [2] 15 b6 [2] 2a aa }

  condition:
    any of them
}