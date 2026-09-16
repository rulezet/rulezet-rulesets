rule TTP_XOR_WriteProcessMemory_b778 {
  strings:
    $key_b778 = { e0 0a [2] d2 28 [2] d4 1d [2] fa 1d [2] c5 01 }

  condition:
    any of them
}