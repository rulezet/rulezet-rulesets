rule TTP_XOR_WriteProcessMemory_c31d {
  strings:
    $key_c31d = { 94 6f [2] a6 4d [2] a0 78 [2] 8e 78 [2] b1 64 }

  condition:
    any of them
}