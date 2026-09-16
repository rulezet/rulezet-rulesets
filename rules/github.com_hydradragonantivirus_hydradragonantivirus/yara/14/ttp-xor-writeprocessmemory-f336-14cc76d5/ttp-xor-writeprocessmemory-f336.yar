rule TTP_XOR_WriteProcessMemory_f336 {
  strings:
    $key_f336 = { a4 44 [2] 96 66 [2] 90 53 [2] be 53 [2] 81 4f }

  condition:
    any of them
}