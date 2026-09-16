rule TTP_XOR_WriteProcessMemory_5cb3 {
  strings:
    $key_5cb3 = { 0b c1 [2] 39 e3 [2] 3f d6 [2] 11 d6 [2] 2e ca }

  condition:
    any of them
}