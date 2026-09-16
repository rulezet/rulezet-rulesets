rule TTP_XOR_WriteProcessMemory_4ee6 {
  strings:
    $key_4ee6 = { 19 94 [2] 2b b6 [2] 2d 83 [2] 03 83 [2] 3c 9f }

  condition:
    any of them
}