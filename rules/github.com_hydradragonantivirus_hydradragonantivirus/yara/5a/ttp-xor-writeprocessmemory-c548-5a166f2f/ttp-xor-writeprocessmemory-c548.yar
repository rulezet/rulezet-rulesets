rule TTP_XOR_WriteProcessMemory_c548 {
  strings:
    $key_c548 = { 92 3a [2] a0 18 [2] a6 2d [2] 88 2d [2] b7 31 }

  condition:
    any of them
}