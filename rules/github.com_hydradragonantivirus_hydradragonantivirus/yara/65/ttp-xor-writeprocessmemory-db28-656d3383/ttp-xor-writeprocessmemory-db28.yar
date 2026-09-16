rule TTP_XOR_WriteProcessMemory_db28 {
  strings:
    $key_db28 = { 8c 5a [2] be 78 [2] b8 4d [2] 96 4d [2] a9 51 }

  condition:
    any of them
}