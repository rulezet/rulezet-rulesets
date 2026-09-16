rule TTP_XOR_WriteProcessMemory_f738 {
  strings:
    $key_f738 = { a0 4a [2] 92 68 [2] 94 5d [2] ba 5d [2] 85 41 }

  condition:
    any of them
}