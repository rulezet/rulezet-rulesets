rule TTP_XOR_WriteProcessMemory_b779 {
  strings:
    $key_b779 = { e0 0b [2] d2 29 [2] d4 1c [2] fa 1c [2] c5 00 }

  condition:
    any of them
}