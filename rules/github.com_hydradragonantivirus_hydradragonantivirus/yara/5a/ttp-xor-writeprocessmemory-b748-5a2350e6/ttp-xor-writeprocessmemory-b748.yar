rule TTP_XOR_WriteProcessMemory_b748 {
  strings:
    $key_b748 = { e0 3a [2] d2 18 [2] d4 2d [2] fa 2d [2] c5 31 }

  condition:
    any of them
}