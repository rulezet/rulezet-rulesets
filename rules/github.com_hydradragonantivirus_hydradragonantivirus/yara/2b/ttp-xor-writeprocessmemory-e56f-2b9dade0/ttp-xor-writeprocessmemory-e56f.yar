rule TTP_XOR_WriteProcessMemory_e56f {
  strings:
    $key_e56f = { b2 1d [2] 80 3f [2] 86 0a [2] a8 0a [2] 97 16 }

  condition:
    any of them
}