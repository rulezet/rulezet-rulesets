rule TTP_XOR_WriteProcessMemory_68d3 {
  strings:
    $key_68d3 = { 3f a1 [2] 0d 83 [2] 0b b6 [2] 25 b6 [2] 1a aa }

  condition:
    any of them
}