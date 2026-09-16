rule TTP_XOR_WriteProcessMemory_6edd {
  strings:
    $key_6edd = { 39 af [2] 0b 8d [2] 0d b8 [2] 23 b8 [2] 1c a4 }

  condition:
    any of them
}