rule TTP_XOR_WriteProcessMemory_c04d {
  strings:
    $key_c04d = { 97 3f [2] a5 1d [2] a3 28 [2] 8d 28 [2] b2 34 }

  condition:
    any of them
}