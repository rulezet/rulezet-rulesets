rule TTP_XOR_WriteProcessMemory_b731 {
  strings:
    $key_b731 = { e0 43 [2] d2 61 [2] d4 54 [2] fa 54 [2] c5 48 }

  condition:
    any of them
}