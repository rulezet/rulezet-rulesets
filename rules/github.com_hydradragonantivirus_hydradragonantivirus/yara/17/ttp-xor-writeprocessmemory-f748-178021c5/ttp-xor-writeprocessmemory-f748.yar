rule TTP_XOR_WriteProcessMemory_f748 {
  strings:
    $key_f748 = { a0 3a [2] 92 18 [2] 94 2d [2] ba 2d [2] 85 31 }

  condition:
    any of them
}