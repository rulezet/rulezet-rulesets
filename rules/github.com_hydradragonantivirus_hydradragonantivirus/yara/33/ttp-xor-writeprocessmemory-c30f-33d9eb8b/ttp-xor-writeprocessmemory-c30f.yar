rule TTP_XOR_WriteProcessMemory_c30f {
  strings:
    $key_c30f = { 94 7d [2] a6 5f [2] a0 6a [2] 8e 6a [2] b1 76 }

  condition:
    any of them
}