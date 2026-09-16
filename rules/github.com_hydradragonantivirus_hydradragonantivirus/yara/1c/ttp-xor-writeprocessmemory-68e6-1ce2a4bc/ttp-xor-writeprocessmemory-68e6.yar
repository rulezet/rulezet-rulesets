rule TTP_XOR_WriteProcessMemory_68e6 {
  strings:
    $key_68e6 = { 3f 94 [2] 0d b6 [2] 0b 83 [2] 25 83 [2] 1a 9f }

  condition:
    any of them
}