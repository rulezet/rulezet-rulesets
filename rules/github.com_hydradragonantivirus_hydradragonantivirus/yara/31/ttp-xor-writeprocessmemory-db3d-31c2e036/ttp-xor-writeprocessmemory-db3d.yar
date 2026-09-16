rule TTP_XOR_WriteProcessMemory_db3d {
  strings:
    $key_db3d = { 8c 4f [2] be 6d [2] b8 58 [2] 96 58 [2] a9 44 }

  condition:
    any of them
}