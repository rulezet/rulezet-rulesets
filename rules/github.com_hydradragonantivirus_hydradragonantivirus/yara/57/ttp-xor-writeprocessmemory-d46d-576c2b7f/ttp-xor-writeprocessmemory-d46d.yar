rule TTP_XOR_WriteProcessMemory_d46d {
  strings:
    $key_d46d = { 83 1f [2] b1 3d [2] b7 08 [2] 99 08 [2] a6 14 }

  condition:
    any of them
}