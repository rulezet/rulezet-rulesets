rule TTP_XOR_WriteProcessMemory_0cd2 {
  strings:
    $key_0cd2 = { 5b a0 [2] 69 82 [2] 6f b7 [2] 41 b7 [2] 7e ab }

  condition:
    any of them
}