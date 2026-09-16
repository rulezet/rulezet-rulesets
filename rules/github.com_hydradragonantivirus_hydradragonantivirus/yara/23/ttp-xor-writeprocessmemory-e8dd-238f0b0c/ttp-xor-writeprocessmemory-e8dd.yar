rule TTP_XOR_WriteProcessMemory_e8dd {
  strings:
    $key_e8dd = { bf af [2] 8d 8d [2] 8b b8 [2] a5 b8 [2] 9a a4 }

  condition:
    any of them
}