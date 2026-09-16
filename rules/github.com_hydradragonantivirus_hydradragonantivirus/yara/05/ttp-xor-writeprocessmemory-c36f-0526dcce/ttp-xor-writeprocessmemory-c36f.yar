rule TTP_XOR_WriteProcessMemory_c36f {
  strings:
    $key_c36f = { 94 1d [2] a6 3f [2] a0 0a [2] 8e 0a [2] b1 16 }

  condition:
    any of them
}