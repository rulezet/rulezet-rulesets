rule TTP_XOR_WriteProcessMemory_b74d {
  strings:
    $key_b74d = { e0 3f [2] d2 1d [2] d4 28 [2] fa 28 [2] c5 34 }

  condition:
    any of them
}