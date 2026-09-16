rule TTP_XOR_WriteProcessMemory_7980 {
  strings:
    $key_7980 = { 2e f2 [2] 1c d0 [2] 1a e5 [2] 34 e5 [2] 0b f9 }

  condition:
    any of them
}