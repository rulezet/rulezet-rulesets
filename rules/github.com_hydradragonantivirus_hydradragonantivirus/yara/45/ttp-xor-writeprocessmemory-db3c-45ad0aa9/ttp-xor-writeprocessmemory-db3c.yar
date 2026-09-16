rule TTP_XOR_WriteProcessMemory_db3c {
  strings:
    $key_db3c = { 8c 4e [2] be 6c [2] b8 59 [2] 96 59 [2] a9 45 }

  condition:
    any of them
}