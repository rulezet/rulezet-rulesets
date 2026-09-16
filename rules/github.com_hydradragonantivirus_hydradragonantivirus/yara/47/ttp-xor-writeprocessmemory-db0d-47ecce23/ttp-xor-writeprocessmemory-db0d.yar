rule TTP_XOR_WriteProcessMemory_db0d {
  strings:
    $key_db0d = { 8c 7f [2] be 5d [2] b8 68 [2] 96 68 [2] a9 74 }

  condition:
    any of them
}