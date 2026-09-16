rule TTP_XOR_WriteProcessMemory_0cd7 {
  strings:
    $key_0cd7 = { 5b a5 [2] 69 87 [2] 6f b2 [2] 41 b2 [2] 7e ae }

  condition:
    any of them
}