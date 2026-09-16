rule TTP_XOR_WriteProcessMemory_b754 {
  strings:
    $key_b754 = { e0 26 [2] d2 04 [2] d4 31 [2] fa 31 [2] c5 2d }

  condition:
    any of them
}