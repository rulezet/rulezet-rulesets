rule TTP_XOR_WriteProcessMemory_1c12 {
  strings:
    $key_1c12 = { 4b 60 [2] 79 42 [2] 7f 77 [2] 51 77 [2] 6e 6b }

  condition:
    any of them
}