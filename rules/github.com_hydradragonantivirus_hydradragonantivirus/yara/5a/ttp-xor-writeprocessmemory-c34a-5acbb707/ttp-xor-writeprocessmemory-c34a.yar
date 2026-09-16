rule TTP_XOR_WriteProcessMemory_c34a {
  strings:
    $key_c34a = { 94 38 [2] a6 1a [2] a0 2f [2] 8e 2f [2] b1 33 }

  condition:
    any of them
}