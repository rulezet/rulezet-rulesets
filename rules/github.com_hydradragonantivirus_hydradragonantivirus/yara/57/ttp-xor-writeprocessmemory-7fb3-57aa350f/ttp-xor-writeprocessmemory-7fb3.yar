rule TTP_XOR_WriteProcessMemory_7fb3 {
  strings:
    $key_7fb3 = { 28 c1 [2] 1a e3 [2] 1c d6 [2] 32 d6 [2] 0d ca }

  condition:
    any of them
}