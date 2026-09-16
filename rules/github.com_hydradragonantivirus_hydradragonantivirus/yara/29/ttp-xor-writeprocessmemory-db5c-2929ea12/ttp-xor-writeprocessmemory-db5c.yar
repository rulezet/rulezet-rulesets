rule TTP_XOR_WriteProcessMemory_db5c {
  strings:
    $key_db5c = { 8c 2e [2] be 0c [2] b8 39 [2] 96 39 [2] a9 25 }

  condition:
    any of them
}