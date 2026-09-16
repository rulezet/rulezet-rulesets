rule TTP_XOR_WriteProcessMemory_47dd {
  strings:
    $key_47dd = { 10 af [2] 22 8d [2] 24 b8 [2] 0a b8 [2] 35 a4 }

  condition:
    any of them
}