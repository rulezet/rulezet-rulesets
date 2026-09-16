rule TTP_XOR_WriteProcessMemory_f7e8 {
  strings:
    $key_f7e8 = { a0 9a [2] 92 b8 [2] 94 8d [2] ba 8d [2] 85 91 }

  condition:
    any of them
}