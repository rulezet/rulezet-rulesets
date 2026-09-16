rule TTP_XOR_WriteProcessMemory_a52d {
  strings:
    $key_a52d = { f2 5f [2] c0 7d [2] c6 48 [2] e8 48 [2] d7 54 }

  condition:
    any of them
}