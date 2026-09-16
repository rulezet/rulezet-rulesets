rule TTP_XOR_WriteProcessMemory_db4d {
  strings:
    $key_db4d = { 8c 3f [2] be 1d [2] b8 28 [2] 96 28 [2] a9 34 }

  condition:
    any of them
}