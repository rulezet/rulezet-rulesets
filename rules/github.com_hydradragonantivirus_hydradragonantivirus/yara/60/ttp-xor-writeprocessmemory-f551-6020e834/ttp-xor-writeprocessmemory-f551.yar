rule TTP_XOR_WriteProcessMemory_f551 {
  strings:
    $key_f551 = { a2 23 [2] 90 01 [2] 96 34 [2] b8 34 [2] 87 28 }

  condition:
    any of them
}