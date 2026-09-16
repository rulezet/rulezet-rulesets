rule TTP_XOR_WriteProcessMemory_7cc0 {
  strings:
    $key_7cc0 = { 2b b2 [2] 19 90 [2] 1f a5 [2] 31 a5 [2] 0e b9 }

  condition:
    any of them
}