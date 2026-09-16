rule TTP_XOR_WriteProcessMemory_f74f {
  strings:
    $key_f74f = { a0 3d [2] 92 1f [2] 94 2a [2] ba 2a [2] 85 36 }

  condition:
    any of them
}