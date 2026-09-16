rule TTP_XOR_WriteProcessMemory_f77d {
  strings:
    $key_f77d = { a0 0f [2] 92 2d [2] 94 18 [2] ba 18 [2] 85 04 }

  condition:
    any of them
}