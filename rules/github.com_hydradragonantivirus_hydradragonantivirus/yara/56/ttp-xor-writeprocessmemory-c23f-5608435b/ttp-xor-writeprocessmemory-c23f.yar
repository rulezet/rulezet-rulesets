rule TTP_XOR_WriteProcessMemory_c23f {
  strings:
    $key_c23f = { 95 4d [2] a7 6f [2] a1 5a [2] 8f 5a [2] b0 46 }

  condition:
    any of them
}