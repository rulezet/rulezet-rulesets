rule TTP_XOR_WriteProcessMemory_41dd {
  strings:
    $key_41dd = { 16 af [2] 24 8d [2] 22 b8 [2] 0c b8 [2] 33 a4 }

  condition:
    any of them
}