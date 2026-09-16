rule TTP_XOR_WriteProcessMemory_db41 {
  strings:
    $key_db41 = { 8c 33 [2] be 11 [2] b8 24 [2] 96 24 [2] a9 38 }

  condition:
    any of them
}