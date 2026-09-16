rule TTP_XOR_WriteProcessMemory_c15f {
  strings:
    $key_c15f = { 96 2d [2] a4 0f [2] a2 3a [2] 8c 3a [2] b3 26 }

  condition:
    any of them
}