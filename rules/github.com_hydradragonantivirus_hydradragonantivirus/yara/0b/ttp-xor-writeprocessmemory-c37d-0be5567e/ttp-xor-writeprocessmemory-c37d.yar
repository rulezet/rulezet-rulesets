rule TTP_XOR_WriteProcessMemory_c37d {
  strings:
    $key_c37d = { 94 0f [2] a6 2d [2] a0 18 [2] 8e 18 [2] b1 04 }

  condition:
    any of them
}