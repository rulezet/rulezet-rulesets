rule TTP_XOR_WriteProcessMemory_d258 {
  strings:
    $key_d258 = { 85 2a [2] b7 08 [2] b1 3d [2] 9f 3d [2] a0 21 }

  condition:
    any of them
}