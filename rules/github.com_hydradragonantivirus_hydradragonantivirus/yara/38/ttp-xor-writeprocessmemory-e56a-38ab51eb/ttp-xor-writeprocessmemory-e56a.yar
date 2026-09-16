rule TTP_XOR_WriteProcessMemory_e56a {
  strings:
    $key_e56a = { b2 18 [2] 80 3a [2] 86 0f [2] a8 0f [2] 97 13 }

  condition:
    any of them
}