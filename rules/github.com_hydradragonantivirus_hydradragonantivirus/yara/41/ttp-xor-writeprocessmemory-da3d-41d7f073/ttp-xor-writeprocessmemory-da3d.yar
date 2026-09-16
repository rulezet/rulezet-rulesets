rule TTP_XOR_WriteProcessMemory_da3d {
  strings:
    $key_da3d = { 8d 4f [2] bf 6d [2] b9 58 [2] 97 58 [2] a8 44 }

  condition:
    any of them
}