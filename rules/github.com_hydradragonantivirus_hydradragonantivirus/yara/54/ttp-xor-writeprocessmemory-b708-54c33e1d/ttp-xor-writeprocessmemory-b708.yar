rule TTP_XOR_WriteProcessMemory_b708 {
  strings:
    $key_b708 = { e0 7a [2] d2 58 [2] d4 6d [2] fa 6d [2] c5 71 }

  condition:
    any of them
}