rule TTP_XOR_WriteProcessMemory_c058 {
  strings:
    $key_c058 = { 97 2a [2] a5 08 [2] a3 3d [2] 8d 3d [2] b2 21 }

  condition:
    any of them
}