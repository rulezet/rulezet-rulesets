rule TTP_XOR_WriteProcessMemory_c448 {
  strings:
    $key_c448 = { 93 3a [2] a1 18 [2] a7 2d [2] 89 2d [2] b6 31 }

  condition:
    any of them
}