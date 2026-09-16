rule TTP_XOR_WriteProcessMemory_b749 {
  strings:
    $key_b749 = { e0 3b [2] d2 19 [2] d4 2c [2] fa 2c [2] c5 30 }

  condition:
    any of them
}