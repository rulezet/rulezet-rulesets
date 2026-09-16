rule TTP_XOR_WriteProcessMemory_db7c {
  strings:
    $key_db7c = { 8c 0e [2] be 2c [2] b8 19 [2] 96 19 [2] a9 05 }

  condition:
    any of them
}