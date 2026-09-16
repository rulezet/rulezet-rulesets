rule TTP_XOR_WriteProcessMemory_b7f5 {
  strings:
    $key_b7f5 = { e0 87 [2] d2 a5 [2] d4 90 [2] fa 90 [2] c5 8c }

  condition:
    any of them
}