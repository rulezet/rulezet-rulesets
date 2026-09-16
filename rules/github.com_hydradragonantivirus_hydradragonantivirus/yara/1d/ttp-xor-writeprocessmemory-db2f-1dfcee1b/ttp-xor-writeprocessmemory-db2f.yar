rule TTP_XOR_WriteProcessMemory_db2f {
  strings:
    $key_db2f = { 8c 5d [2] be 7f [2] b8 4a [2] 96 4a [2] a9 56 }

  condition:
    any of them
}