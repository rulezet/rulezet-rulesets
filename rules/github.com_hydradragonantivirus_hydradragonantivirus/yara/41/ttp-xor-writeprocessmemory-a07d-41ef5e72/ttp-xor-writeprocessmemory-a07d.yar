rule TTP_XOR_WriteProcessMemory_a07d {
  strings:
    $key_a07d = { f7 0f [2] c5 2d [2] c3 18 [2] ed 18 [2] d2 04 }

  condition:
    any of them
}