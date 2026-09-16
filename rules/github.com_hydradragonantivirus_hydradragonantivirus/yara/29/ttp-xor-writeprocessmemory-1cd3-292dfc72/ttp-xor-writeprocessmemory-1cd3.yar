rule TTP_XOR_WriteProcessMemory_1cd3 {
  strings:
    $key_1cd3 = { 4b a1 [2] 79 83 [2] 7f b6 [2] 51 b6 [2] 6e aa }

  condition:
    any of them
}