rule TTP_XOR_WriteProcessMemory_db18 {
  strings:
    $key_db18 = { 8c 6a [2] be 48 [2] b8 7d [2] 96 7d [2] a9 61 }

  condition:
    any of them
}