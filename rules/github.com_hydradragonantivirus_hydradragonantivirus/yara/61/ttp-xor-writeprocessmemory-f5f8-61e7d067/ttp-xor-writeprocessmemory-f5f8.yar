rule TTP_XOR_WriteProcessMemory_f5f8 {
  strings:
    $key_f5f8 = { a2 8a [2] 90 a8 [2] 96 9d [2] b8 9d [2] 87 81 }

  condition:
    any of them
}