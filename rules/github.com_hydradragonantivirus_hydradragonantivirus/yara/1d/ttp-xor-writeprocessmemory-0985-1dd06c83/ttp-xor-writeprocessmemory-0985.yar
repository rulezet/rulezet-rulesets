rule TTP_XOR_WriteProcessMemory_0985 {
  strings:
    $key_0985 = { 5e f7 [2] 6c d5 [2] 6a e0 [2] 44 e0 [2] 7b fc }

  condition:
    any of them
}