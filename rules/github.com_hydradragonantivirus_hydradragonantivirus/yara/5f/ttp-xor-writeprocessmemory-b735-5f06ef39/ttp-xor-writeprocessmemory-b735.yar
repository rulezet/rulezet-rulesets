rule TTP_XOR_WriteProcessMemory_b735 {
  strings:
    $key_b735 = { e0 47 [2] d2 65 [2] d4 50 [2] fa 50 [2] c5 4c }

  condition:
    any of them
}