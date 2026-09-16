rule TTP_XOR_WriteProcessMemory_f3dd {
  strings:
    $key_f3dd = { a4 af [2] 96 8d [2] 90 b8 [2] be b8 [2] 81 a4 }

  condition:
    any of them
}