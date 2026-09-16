rule TTP_XOR_WriteProcessMemory_d26d {
  strings:
    $key_d26d = { 85 1f [2] b7 3d [2] b1 08 [2] 9f 08 [2] a0 14 }

  condition:
    any of them
}