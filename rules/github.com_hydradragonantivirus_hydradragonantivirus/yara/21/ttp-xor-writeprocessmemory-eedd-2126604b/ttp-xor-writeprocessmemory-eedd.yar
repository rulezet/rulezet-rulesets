rule TTP_XOR_WriteProcessMemory_eedd {
  strings:
    $key_eedd = { b9 af [2] 8b 8d [2] 8d b8 [2] a3 b8 [2] 9c a4 }

  condition:
    any of them
}