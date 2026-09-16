rule TTP_XOR_WriteProcessMemory_6c12 {
  strings:
    $key_6c12 = { 3b 60 [2] 09 42 [2] 0f 77 [2] 21 77 [2] 1e 6b }

  condition:
    any of them
}