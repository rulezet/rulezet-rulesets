rule TTP_XOR_WriteProcessMemory_c24f {
  strings:
    $key_c24f = { 95 3d [2] a7 1f [2] a1 2a [2] 8f 2a [2] b0 36 }

  condition:
    any of them
}