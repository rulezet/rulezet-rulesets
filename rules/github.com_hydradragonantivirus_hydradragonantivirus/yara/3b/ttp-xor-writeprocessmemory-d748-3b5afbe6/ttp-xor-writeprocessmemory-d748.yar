rule TTP_XOR_WriteProcessMemory_d748 {
  strings:
    $key_d748 = { 80 3a [2] b2 18 [2] b4 2d [2] 9a 2d [2] a5 31 }

  condition:
    any of them
}