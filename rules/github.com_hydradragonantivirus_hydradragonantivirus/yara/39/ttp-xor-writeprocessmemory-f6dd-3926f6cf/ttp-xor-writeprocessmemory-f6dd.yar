rule TTP_XOR_WriteProcessMemory_f6dd {
  strings:
    $key_f6dd = { a1 af [2] 93 8d [2] 95 b8 [2] bb b8 [2] 84 a4 }

  condition:
    any of them
}