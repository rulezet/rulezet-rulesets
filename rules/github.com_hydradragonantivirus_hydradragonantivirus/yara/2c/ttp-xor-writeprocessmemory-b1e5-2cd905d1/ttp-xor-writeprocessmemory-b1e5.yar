rule TTP_XOR_WriteProcessMemory_b1e5 {
  strings:
    $key_b1e5 = { e6 97 [2] d4 b5 [2] d2 80 [2] fc 80 [2] c3 9c }

  condition:
    any of them
}