rule TTP_XOR_WriteProcessMemory_1ef6 {
  strings:
    $key_1ef6 = { 49 84 [2] 7b a6 [2] 7d 93 [2] 53 93 [2] 6c 8f }

  condition:
    any of them
}