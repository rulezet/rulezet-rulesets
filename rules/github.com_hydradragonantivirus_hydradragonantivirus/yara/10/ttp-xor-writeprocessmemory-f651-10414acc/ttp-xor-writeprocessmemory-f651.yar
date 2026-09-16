rule TTP_XOR_WriteProcessMemory_f651 {
  strings:
    $key_f651 = { a1 23 [2] 93 01 [2] 95 34 [2] bb 34 [2] 84 28 }

  condition:
    any of them
}