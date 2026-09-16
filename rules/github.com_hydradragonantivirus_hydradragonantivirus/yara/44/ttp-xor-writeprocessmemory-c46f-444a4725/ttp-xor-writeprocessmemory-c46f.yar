rule TTP_XOR_WriteProcessMemory_c46f {
  strings:
    $key_c46f = { 93 1d [2] a1 3f [2] a7 0a [2] 89 0a [2] b6 16 }

  condition:
    any of them
}