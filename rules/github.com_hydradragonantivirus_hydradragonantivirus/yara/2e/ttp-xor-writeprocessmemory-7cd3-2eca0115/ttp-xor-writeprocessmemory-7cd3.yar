rule TTP_XOR_WriteProcessMemory_7cd3 {
  strings:
    $key_7cd3 = { 2b a1 [2] 19 83 [2] 1f b6 [2] 31 b6 [2] 0e aa }

  condition:
    any of them
}