rule TTP_XOR_WriteProcessMemory_c33f {
  strings:
    $key_c33f = { 94 4d [2] a6 6f [2] a0 5a [2] 8e 5a [2] b1 46 }

  condition:
    any of them
}