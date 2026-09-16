rule TTP_XOR_WriteProcessMemory_e518 {
  strings:
    $key_e518 = { b2 6a [2] 80 48 [2] 86 7d [2] a8 7d [2] 97 61 }

  condition:
    any of them
}