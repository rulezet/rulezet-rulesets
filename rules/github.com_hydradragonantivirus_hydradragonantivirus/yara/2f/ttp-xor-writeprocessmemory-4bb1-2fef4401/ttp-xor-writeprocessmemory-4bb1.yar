rule TTP_XOR_WriteProcessMemory_4bb1 {
  strings:
    $key_4bb1 = { 1c c3 [2] 2e e1 [2] 28 d4 [2] 06 d4 [2] 39 c8 }

  condition:
    any of them
}