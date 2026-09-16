rule TTP_XOR_WriteProcessMemory_d16d {
  strings:
    $key_d16d = { 86 1f [2] b4 3d [2] b2 08 [2] 9c 08 [2] a3 14 }

  condition:
    any of them
}