rule TTP_XOR_WriteProcessMemory_b765 {
  strings:
    $key_b765 = { e0 17 [2] d2 35 [2] d4 00 [2] fa 00 [2] c5 1c }

  condition:
    any of them
}