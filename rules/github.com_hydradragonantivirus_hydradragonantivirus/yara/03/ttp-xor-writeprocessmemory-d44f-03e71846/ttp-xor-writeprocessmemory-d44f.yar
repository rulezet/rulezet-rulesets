rule TTP_XOR_WriteProcessMemory_d44f {
  strings:
    $key_d44f = { 83 3d [2] b1 1f [2] b7 2a [2] 99 2a [2] a6 36 }

  condition:
    any of them
}