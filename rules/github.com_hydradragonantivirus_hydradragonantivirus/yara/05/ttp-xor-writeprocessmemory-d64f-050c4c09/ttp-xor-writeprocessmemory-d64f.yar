rule TTP_XOR_WriteProcessMemory_d64f {
  strings:
    $key_d64f = { 81 3d [2] b3 1f [2] b5 2a [2] 9b 2a [2] a4 36 }

  condition:
    any of them
}