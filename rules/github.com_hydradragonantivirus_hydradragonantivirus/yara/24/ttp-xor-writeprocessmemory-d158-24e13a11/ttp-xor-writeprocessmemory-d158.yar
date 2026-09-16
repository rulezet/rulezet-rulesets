rule TTP_XOR_WriteProcessMemory_d158 {
  strings:
    $key_d158 = { 86 2a [2] b4 08 [2] b2 3d [2] 9c 3d [2] a3 21 }

  condition:
    any of them
}