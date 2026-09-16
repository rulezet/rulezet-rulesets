rule TTP_XOR_WriteProcessMemory_d458 {
  strings:
    $key_d458 = { 83 2a [2] b1 08 [2] b7 3d [2] 99 3d [2] a6 21 }

  condition:
    any of them
}