rule TTP_XOR_WriteProcessMemory_dba5 {
  strings:
    $key_dba5 = { 8c d7 [2] be f5 [2] b8 c0 [2] 96 c0 [2] a9 dc }

  condition:
    any of them
}