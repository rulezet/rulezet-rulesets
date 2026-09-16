rule TTP_XOR_WriteProcessMemory_d048 {
  strings:
    $key_d048 = { 87 3a [2] b5 18 [2] b3 2d [2] 9d 2d [2] a2 31 }

  condition:
    any of them
}