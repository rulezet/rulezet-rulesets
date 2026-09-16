rule TTP_XOR_WriteProcessMemory_23dd {
  strings:
    $key_23dd = { 74 af [2] 46 8d [2] 40 b8 [2] 6e b8 [2] 51 a4 }

  condition:
    any of them
}