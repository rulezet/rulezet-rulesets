rule TTP_XOR_WriteProcessMemory_7af3 {
  strings:
    $key_7af3 = { 2d 81 [2] 1f a3 [2] 19 96 [2] 37 96 [2] 08 8a }

  condition:
    any of them
}