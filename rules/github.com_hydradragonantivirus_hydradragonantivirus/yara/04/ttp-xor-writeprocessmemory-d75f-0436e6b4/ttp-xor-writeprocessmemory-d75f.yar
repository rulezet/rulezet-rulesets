rule TTP_XOR_WriteProcessMemory_d75f {
  strings:
    $key_d75f = { 80 2d [2] b2 0f [2] b4 3a [2] 9a 3a [2] a5 26 }

  condition:
    any of them
}