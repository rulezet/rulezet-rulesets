rule TTP_XOR_WriteProcessMemory_c75f {
  strings:
    $key_c75f = { 90 2d [2] a2 0f [2] a4 3a [2] 8a 3a [2] b5 26 }

  condition:
    any of them
}