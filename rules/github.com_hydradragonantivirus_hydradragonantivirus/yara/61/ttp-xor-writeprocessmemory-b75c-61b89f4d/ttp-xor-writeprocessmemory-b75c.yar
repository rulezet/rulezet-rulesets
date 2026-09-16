rule TTP_XOR_WriteProcessMemory_b75c {
  strings:
    $key_b75c = { e0 2e [2] d2 0c [2] d4 39 [2] fa 39 [2] c5 25 }

  condition:
    any of them
}