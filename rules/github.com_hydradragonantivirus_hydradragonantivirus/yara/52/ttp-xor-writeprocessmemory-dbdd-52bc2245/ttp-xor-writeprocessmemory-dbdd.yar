rule TTP_XOR_WriteProcessMemory_dbdd {
  strings:
    $key_dbdd = { 8c af [2] be 8d [2] b8 b8 [2] 96 b8 [2] a9 a4 }

  condition:
    any of them
}