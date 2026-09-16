rule TTP_XOR_WriteProcessMemory_e57f {
  strings:
    $key_e57f = { b2 0d [2] 80 2f [2] 86 1a [2] a8 1a [2] 97 06 }

  condition:
    any of them
}