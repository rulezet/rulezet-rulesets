rule TTP_XOR_WriteProcessMemory_e0dd {
  strings:
    $key_e0dd = { b7 af [2] 85 8d [2] 83 b8 [2] ad b8 [2] 92 a4 }

  condition:
    any of them
}