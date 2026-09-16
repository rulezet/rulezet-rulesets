rule TTP_XOR_WriteProcessMemory_4c12 {
  strings:
    $key_4c12 = { 1b 60 [2] 29 42 [2] 2f 77 [2] 01 77 [2] 3e 6b }

  condition:
    any of them
}