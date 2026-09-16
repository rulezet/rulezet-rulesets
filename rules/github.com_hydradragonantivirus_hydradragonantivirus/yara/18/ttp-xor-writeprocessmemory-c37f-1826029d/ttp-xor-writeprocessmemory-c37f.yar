rule TTP_XOR_WriteProcessMemory_c37f {
  strings:
    $key_c37f = { 94 0d [2] a6 2f [2] a0 1a [2] 8e 1a [2] b1 06 }

  condition:
    any of them
}