rule TTP_XOR_WriteProcessMemory_1edd {
  strings:
    $key_1edd = { 49 af [2] 7b 8d [2] 7d b8 [2] 53 b8 [2] 6c a4 }

  condition:
    any of them
}