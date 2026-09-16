rule TTP_XOR_WriteProcessMemory_e54a {
  strings:
    $key_e54a = { b2 38 [2] 80 1a [2] 86 2f [2] a8 2f [2] 97 33 }

  condition:
    any of them
}