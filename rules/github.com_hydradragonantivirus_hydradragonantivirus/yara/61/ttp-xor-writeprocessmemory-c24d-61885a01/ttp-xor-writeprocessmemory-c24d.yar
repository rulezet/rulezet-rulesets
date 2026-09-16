rule TTP_XOR_WriteProcessMemory_c24d {
  strings:
    $key_c24d = { 95 3f [2] a7 1d [2] a1 28 [2] 8f 28 [2] b0 34 }

  condition:
    any of them
}