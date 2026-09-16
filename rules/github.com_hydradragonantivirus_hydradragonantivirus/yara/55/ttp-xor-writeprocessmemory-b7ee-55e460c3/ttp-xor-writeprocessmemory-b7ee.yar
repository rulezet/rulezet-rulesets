rule TTP_XOR_WriteProcessMemory_b7ee {
  strings:
    $key_b7ee = { e0 9c [2] d2 be [2] d4 8b [2] fa 8b [2] c5 97 }

  condition:
    any of them
}