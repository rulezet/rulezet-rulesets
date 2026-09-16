rule TTP_XOR_WriteProcessMemory_5edd {
  strings:
    $key_5edd = { 09 af [2] 3b 8d [2] 3d b8 [2] 13 b8 [2] 2c a4 }

  condition:
    any of them
}