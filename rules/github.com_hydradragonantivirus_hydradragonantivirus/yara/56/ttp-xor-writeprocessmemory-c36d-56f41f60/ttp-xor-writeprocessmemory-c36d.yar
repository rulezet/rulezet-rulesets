rule TTP_XOR_WriteProcessMemory_c36d {
  strings:
    $key_c36d = { 94 1f [2] a6 3d [2] a0 08 [2] 8e 08 [2] b1 14 }

  condition:
    any of them
}