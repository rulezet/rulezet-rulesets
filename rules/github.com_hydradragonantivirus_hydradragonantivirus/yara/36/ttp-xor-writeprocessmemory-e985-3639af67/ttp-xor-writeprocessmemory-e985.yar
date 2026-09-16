rule TTP_XOR_WriteProcessMemory_e985 {
  strings:
    $key_e985 = { be f7 [2] 8c d5 [2] 8a e0 [2] a4 e0 [2] 9b fc }

  condition:
    any of them
}