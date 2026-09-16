rule TTP_XOR_WriteProcessMemory_6cd4 {
  strings:
    $key_6cd4 = { 3b a6 [2] 09 84 [2] 0f b1 [2] 21 b1 [2] 1e ad }

  condition:
    any of them
}