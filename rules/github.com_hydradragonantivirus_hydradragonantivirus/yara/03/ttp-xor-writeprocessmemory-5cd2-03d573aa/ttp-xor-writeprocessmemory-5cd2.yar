rule TTP_XOR_WriteProcessMemory_5cd2 {
  strings:
    $key_5cd2 = { 0b a0 [2] 39 82 [2] 3f b7 [2] 11 b7 [2] 2e ab }

  condition:
    any of them
}