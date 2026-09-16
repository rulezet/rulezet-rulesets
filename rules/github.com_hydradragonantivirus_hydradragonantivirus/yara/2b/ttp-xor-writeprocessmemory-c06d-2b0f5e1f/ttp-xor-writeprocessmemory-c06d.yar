rule TTP_XOR_WriteProcessMemory_c06d {
  strings:
    $key_c06d = { 97 1f [2] a5 3d [2] a3 08 [2] 8d 08 [2] b2 14 }

  condition:
    any of them
}