rule TTP_XOR_WriteProcessMemory_d558 {
  strings:
    $key_d558 = { 82 2a [2] b0 08 [2] b6 3d [2] 98 3d [2] a7 21 }

  condition:
    any of them
}