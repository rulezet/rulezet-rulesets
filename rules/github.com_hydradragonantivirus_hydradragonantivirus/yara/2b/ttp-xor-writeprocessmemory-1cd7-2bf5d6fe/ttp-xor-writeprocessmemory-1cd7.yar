rule TTP_XOR_WriteProcessMemory_1cd7 {
  strings:
    $key_1cd7 = { 4b a5 [2] 79 87 [2] 7f b2 [2] 51 b2 [2] 6e ae }

  condition:
    any of them
}