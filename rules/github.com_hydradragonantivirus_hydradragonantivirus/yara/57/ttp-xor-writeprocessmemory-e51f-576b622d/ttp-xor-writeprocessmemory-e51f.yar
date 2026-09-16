rule TTP_XOR_WriteProcessMemory_e51f {
  strings:
    $key_e51f = { b2 6d [2] 80 4f [2] 86 7a [2] a8 7a [2] 97 66 }

  condition:
    any of them
}