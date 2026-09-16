rule TTP_XOR_WriteProcessMemory_c53f {
  strings:
    $key_c53f = { 92 4d [2] a0 6f [2] a6 5a [2] 88 5a [2] b7 46 }

  condition:
    any of them
}