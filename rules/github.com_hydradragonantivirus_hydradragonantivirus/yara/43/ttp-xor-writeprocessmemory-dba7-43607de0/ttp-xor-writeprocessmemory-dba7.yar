rule TTP_XOR_WriteProcessMemory_dba7 {
  strings:
    $key_dba7 = { 8c d5 [2] be f7 [2] b8 c2 [2] 96 c2 [2] a9 de }

  condition:
    any of them
}