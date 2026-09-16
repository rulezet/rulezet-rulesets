rule TTP_XOR_WriteProcessMemory_b769 {
  strings:
    $key_b769 = { e0 1b [2] d2 39 [2] d4 0c [2] fa 0c [2] c5 10 }

  condition:
    any of them
}