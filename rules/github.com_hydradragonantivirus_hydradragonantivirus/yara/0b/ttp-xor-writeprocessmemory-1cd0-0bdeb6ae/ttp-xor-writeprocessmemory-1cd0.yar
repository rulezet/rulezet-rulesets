rule TTP_XOR_WriteProcessMemory_1cd0 {
  strings:
    $key_1cd0 = { 4b a2 [2] 79 80 [2] 7f b5 [2] 51 b5 [2] 6e a9 }

  condition:
    any of them
}