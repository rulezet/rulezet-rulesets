rule TTP_XOR_WriteProcessMemory_6e46 {
  strings:
    $key_6e46 = { 39 34 [2] 0b 16 [2] 0d 23 [2] 23 23 [2] 1c 3f }

  condition:
    any of them
}