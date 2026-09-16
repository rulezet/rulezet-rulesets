rule TTP_XOR_WriteProcessMemory_5cd6 {
  strings:
    $key_5cd6 = { 0b a4 [2] 39 86 [2] 3f b3 [2] 11 b3 [2] 2e af }

  condition:
    any of them
}