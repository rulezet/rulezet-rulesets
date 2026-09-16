rule TTP_XOR_WriteProcessMemory_dba9 {
  strings:
    $key_dba9 = { 8c db [2] be f9 [2] b8 cc [2] 96 cc [2] a9 d0 }

  condition:
    any of them
}