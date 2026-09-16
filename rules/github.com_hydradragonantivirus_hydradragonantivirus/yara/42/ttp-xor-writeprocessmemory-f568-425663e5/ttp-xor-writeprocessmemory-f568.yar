rule TTP_XOR_WriteProcessMemory_f568 {
  strings:
    $key_f568 = { a2 1a [2] 90 38 [2] 96 0d [2] b8 0d [2] 87 11 }

  condition:
    any of them
}