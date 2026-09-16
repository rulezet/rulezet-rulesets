rule TTP_XOR_WriteProcessMemory_b145 {
  strings:
    $key_b145 = { e6 37 [2] d4 15 [2] d2 20 [2] fc 20 [2] c3 3c }

  condition:
    any of them
}