rule TTP_XOR_WriteProcessMemory_dba6 {
  strings:
    $key_dba6 = { 8c d4 [2] be f6 [2] b8 c3 [2] 96 c3 [2] a9 df }

  condition:
    any of them
}