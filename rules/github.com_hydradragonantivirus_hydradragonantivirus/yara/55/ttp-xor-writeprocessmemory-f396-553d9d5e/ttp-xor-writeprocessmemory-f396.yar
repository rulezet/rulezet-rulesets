rule TTP_XOR_WriteProcessMemory_f396 {
  strings:
    $key_f396 = { a4 e4 [2] 96 c6 [2] 90 f3 [2] be f3 [2] 81 ef }

  condition:
    any of them
}