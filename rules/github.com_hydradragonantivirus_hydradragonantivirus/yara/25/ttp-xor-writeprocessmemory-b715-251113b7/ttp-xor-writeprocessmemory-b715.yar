rule TTP_XOR_WriteProcessMemory_b715 {
  strings:
    $key_b715 = { e0 67 [2] d2 45 [2] d4 70 [2] fa 70 [2] c5 6c }

  condition:
    any of them
}