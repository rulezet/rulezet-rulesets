rule TTP_XOR_WriteProcessMemory_d74f {
  strings:
    $key_d74f = { 80 3d [2] b2 1f [2] b4 2a [2] 9a 2a [2] a5 36 }

  condition:
    any of them
}