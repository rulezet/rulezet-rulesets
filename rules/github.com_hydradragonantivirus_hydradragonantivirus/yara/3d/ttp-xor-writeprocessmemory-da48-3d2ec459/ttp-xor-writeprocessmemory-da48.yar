rule TTP_XOR_WriteProcessMemory_da48 {
  strings:
    $key_da48 = { 8d 3a [2] bf 18 [2] b9 2d [2] 97 2d [2] a8 31 }

  condition:
    any of them
}