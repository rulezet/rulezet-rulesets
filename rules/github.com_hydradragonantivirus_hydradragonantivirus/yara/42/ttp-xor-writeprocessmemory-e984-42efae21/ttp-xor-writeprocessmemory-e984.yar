rule TTP_XOR_WriteProcessMemory_e984 {
  strings:
    $key_e984 = { be f6 [2] 8c d4 [2] 8a e1 [2] a4 e1 [2] 9b fd }

  condition:
    any of them
}