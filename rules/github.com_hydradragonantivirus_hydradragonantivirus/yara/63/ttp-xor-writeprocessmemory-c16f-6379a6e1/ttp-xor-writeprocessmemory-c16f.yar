rule TTP_XOR_WriteProcessMemory_c16f {
  strings:
    $key_c16f = { 96 1d [2] a4 3f [2] a2 0a [2] 8c 0a [2] b3 16 }

  condition:
    any of them
}