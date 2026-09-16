rule TTP_XOR_WriteProcessMemory_0cb3 {
  strings:
    $key_0cb3 = { 5b c1 [2] 69 e3 [2] 6f d6 [2] 41 d6 [2] 7e ca }

  condition:
    any of them
}