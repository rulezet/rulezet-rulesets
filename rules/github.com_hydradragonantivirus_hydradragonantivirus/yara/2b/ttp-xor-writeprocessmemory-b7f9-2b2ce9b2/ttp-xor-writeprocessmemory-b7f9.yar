rule TTP_XOR_WriteProcessMemory_b7f9 {
  strings:
    $key_b7f9 = { e0 8b [2] d2 a9 [2] d4 9c [2] fa 9c [2] c5 80 }

  condition:
    any of them
}