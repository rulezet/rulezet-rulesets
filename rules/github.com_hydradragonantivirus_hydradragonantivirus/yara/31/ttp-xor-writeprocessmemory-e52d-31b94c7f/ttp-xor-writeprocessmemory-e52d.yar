rule TTP_XOR_WriteProcessMemory_e52d {
  strings:
    $key_e52d = { b2 5f [2] 80 7d [2] 86 48 [2] a8 48 [2] 97 54 }

  condition:
    any of them
}