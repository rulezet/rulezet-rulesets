rule TTP_XOR_WriteProcessMemory_2ef6 {
  strings:
    $key_2ef6 = { 79 84 [2] 4b a6 [2] 4d 93 [2] 63 93 [2] 5c 8f }

  condition:
    any of them
}