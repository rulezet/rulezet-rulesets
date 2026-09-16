rule TTP_XOR_WriteProcessMemory_dba8 {
  strings:
    $key_dba8 = { 8c da [2] be f8 [2] b8 cd [2] 96 cd [2] a9 d1 }

  condition:
    any of them
}