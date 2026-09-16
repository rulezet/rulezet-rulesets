rule TTP_XOR_WriteProcessMemory_27dd {
  strings:
    $key_27dd = { 70 af [2] 42 8d [2] 44 b8 [2] 6a b8 [2] 55 a4 }

  condition:
    any of them
}