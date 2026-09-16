rule TTP_XOR_WriteProcessMemory_fa3d {
  strings:
    $key_fa3d = { ad 4f [2] 9f 6d [2] 99 58 [2] b7 58 [2] 88 44 }

  condition:
    any of them
}