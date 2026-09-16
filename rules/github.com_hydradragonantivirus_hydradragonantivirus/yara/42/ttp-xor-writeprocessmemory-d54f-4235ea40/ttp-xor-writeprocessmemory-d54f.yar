rule TTP_XOR_WriteProcessMemory_d54f {
  strings:
    $key_d54f = { 82 3d [2] b0 1f [2] b6 2a [2] 98 2a [2] a7 36 }

  condition:
    any of them
}