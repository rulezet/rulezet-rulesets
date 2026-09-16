rule TTP_XOR_WriteProcessMemory_6ef6 {
  strings:
    $key_6ef6 = { 39 84 [2] 0b a6 [2] 0d 93 [2] 23 93 [2] 1c 8f }

  condition:
    any of them
}