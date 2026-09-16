rule TTP_XOR_WriteProcessMemory_db29 {
  strings:
    $key_db29 = { 8c 5b [2] be 79 [2] b8 4c [2] 96 4c [2] a9 50 }

  condition:
    any of them
}