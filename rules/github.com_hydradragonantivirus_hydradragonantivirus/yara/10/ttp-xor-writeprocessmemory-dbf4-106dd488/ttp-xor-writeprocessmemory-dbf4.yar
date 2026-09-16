rule TTP_XOR_WriteProcessMemory_dbf4 {
  strings:
    $key_dbf4 = { 8c 86 [2] be a4 [2] b8 91 [2] 96 91 [2] a9 8d }

  condition:
    any of them
}