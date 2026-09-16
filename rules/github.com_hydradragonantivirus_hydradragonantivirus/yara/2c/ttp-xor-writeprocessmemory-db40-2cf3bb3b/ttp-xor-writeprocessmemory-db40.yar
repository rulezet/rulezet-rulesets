rule TTP_XOR_WriteProcessMemory_db40 {
  strings:
    $key_db40 = { 8c 32 [2] be 10 [2] b8 25 [2] 96 25 [2] a9 39 }

  condition:
    any of them
}