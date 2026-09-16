rule TTP_XOR_WriteProcessMemory_2cd4 {
  strings:
    $key_2cd4 = { 7b a6 [2] 49 84 [2] 4f b1 [2] 61 b1 [2] 5e ad }

  condition:
    any of them
}