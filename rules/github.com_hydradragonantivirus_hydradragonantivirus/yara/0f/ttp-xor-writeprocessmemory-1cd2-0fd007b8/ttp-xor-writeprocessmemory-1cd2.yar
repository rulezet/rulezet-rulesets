rule TTP_XOR_WriteProcessMemory_1cd2 {
  strings:
    $key_1cd2 = { 4b a0 [2] 79 82 [2] 7f b7 [2] 51 b7 [2] 6e ab }

  condition:
    any of them
}