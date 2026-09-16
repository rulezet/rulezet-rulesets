rule TTP_XOR_WriteProcessMemory_17dd {
  strings:
    $key_17dd = { 40 af [2] 72 8d [2] 74 b8 [2] 5a b8 [2] 65 a4 }

  condition:
    any of them
}