rule TTP_XOR_WriteProcessMemory_b718 {
  strings:
    $key_b718 = { e0 6a [2] d2 48 [2] d4 7d [2] fa 7d [2] c5 61 }

  condition:
    any of them
}