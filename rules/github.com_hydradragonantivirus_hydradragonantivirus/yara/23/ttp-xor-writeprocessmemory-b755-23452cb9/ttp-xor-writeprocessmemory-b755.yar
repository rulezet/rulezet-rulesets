rule TTP_XOR_WriteProcessMemory_b755 {
  strings:
    $key_b755 = { e0 27 [2] d2 05 [2] d4 30 [2] fa 30 [2] c5 2c }

  condition:
    any of them
}