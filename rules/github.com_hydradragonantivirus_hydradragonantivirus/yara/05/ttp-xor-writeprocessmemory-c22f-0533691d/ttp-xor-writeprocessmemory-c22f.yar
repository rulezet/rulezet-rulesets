rule TTP_XOR_WriteProcessMemory_c22f {
  strings:
    $key_c22f = { 95 5d [2] a7 7f [2] a1 4a [2] 8f 4a [2] b0 56 }

  condition:
    any of them
}