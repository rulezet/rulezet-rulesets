rule TTP_XOR_WriteProcessMemory_b71d {
  strings:
    $key_b71d = { e0 6f [2] d2 4d [2] d4 78 [2] fa 78 [2] c5 64 }

  condition:
    any of them
}