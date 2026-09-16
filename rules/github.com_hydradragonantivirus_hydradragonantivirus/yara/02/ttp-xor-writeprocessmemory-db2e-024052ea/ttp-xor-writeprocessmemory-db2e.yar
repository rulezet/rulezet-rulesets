rule TTP_XOR_WriteProcessMemory_db2e {
  strings:
    $key_db2e = { 8c 5c [2] be 7e [2] b8 4b [2] 96 4b [2] a9 57 }

  condition:
    any of them
}