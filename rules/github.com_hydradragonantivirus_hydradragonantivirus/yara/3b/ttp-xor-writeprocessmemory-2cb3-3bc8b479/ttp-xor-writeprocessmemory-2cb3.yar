rule TTP_XOR_WriteProcessMemory_2cb3 {
  strings:
    $key_2cb3 = { 7b c1 [2] 49 e3 [2] 4f d6 [2] 61 d6 [2] 5e ca }

  condition:
    any of them
}