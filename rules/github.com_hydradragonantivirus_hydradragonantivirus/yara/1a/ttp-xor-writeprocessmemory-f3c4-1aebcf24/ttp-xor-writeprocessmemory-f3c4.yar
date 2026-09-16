rule TTP_XOR_WriteProcessMemory_f3c4 {
  strings:
    $key_f3c4 = { a4 b6 [2] 96 94 [2] 90 a1 [2] be a1 [2] 81 bd }

  condition:
    any of them
}