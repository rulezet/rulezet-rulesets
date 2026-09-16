rule TTP_XOR_WriteProcessMemory_c258 {
  strings:
    $key_c258 = { 95 2a [2] a7 08 [2] a1 3d [2] 8f 3d [2] b0 21 }

  condition:
    any of them
}