rule TTP_XOR_WriteProcessMemory_d14f {
  strings:
    $key_d14f = { 86 3d [2] b4 1f [2] b2 2a [2] 9c 2a [2] a3 36 }

  condition:
    any of them
}