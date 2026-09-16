rule TTP_XOR_WriteProcessMemory_c341 {
  strings:
    $key_c341 = { 94 33 [2] a6 11 [2] a0 24 [2] 8e 24 [2] b1 38 }

  condition:
    any of them
}