rule TTP_XOR_WriteProcessMemory_db2a {
  strings:
    $key_db2a = { 8c 58 [2] be 7a [2] b8 4f [2] 96 4f [2] a9 53 }

  condition:
    any of them
}