rule TTP_XOR_WriteProcessMemory_e55a {
  strings:
    $key_e55a = { b2 28 [2] 80 0a [2] 86 3f [2] a8 3f [2] 97 23 }

  condition:
    any of them
}