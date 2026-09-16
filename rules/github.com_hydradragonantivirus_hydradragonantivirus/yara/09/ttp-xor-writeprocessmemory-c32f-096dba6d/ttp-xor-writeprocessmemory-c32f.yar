rule TTP_XOR_WriteProcessMemory_c32f {
  strings:
    $key_c32f = { 94 5d [2] a6 7f [2] a0 4a [2] 8e 4a [2] b1 56 }

  condition:
    any of them
}