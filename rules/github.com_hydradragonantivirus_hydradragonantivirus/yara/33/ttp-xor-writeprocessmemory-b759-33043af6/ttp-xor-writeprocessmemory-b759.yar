rule TTP_XOR_WriteProcessMemory_b759 {
  strings:
    $key_b759 = { e0 2b [2] d2 09 [2] d4 3c [2] fa 3c [2] c5 20 }

  condition:
    any of them
}