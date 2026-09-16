rule TTP_XOR_WriteProcessMemory_da97 {
  strings:
    $key_da97 = { 8d e5 [2] bf c7 [2] b9 f2 [2] 97 f2 [2] a8 ee }

  condition:
    any of them
}