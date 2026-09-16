rule TTP_XOR_WriteProcessMemory_7de6 {
  strings:
    $key_7de6 = { 2a 94 [2] 18 b6 [2] 1e 83 [2] 30 83 [2] 0f 9f }

  condition:
    any of them
}