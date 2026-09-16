rule TTP_XOR_WriteProcessMemory_db60 {
  strings:
    $key_db60 = { 8c 12 [2] be 30 [2] b8 05 [2] 96 05 [2] a9 19 }

  condition:
    any of them
}