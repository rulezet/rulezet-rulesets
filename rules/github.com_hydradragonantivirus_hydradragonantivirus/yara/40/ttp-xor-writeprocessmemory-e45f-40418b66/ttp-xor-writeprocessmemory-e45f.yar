rule TTP_XOR_WriteProcessMemory_e45f {
  strings:
    $key_e45f = { b3 2d [2] 81 0f [2] 87 3a [2] a9 3a [2] 96 26 }

  condition:
    any of them
}