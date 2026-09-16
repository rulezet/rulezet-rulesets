rule TTP_XOR_WriteProcessMemory_a02d {
  strings:
    $key_a02d = { f7 5f [2] c5 7d [2] c3 48 [2] ed 48 [2] d2 54 }

  condition:
    any of them
}