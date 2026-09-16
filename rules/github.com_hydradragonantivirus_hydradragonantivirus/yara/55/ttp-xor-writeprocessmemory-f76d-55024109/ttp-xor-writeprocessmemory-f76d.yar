rule TTP_XOR_WriteProcessMemory_f76d {
  strings:
    $key_f76d = { a0 1f [2] 92 3d [2] 94 08 [2] ba 08 [2] 85 14 }

  condition:
    any of them
}