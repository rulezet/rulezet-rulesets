rule TTP_XOR_WriteProcessMemory_b76e {
  strings:
    $key_b76e = { e0 1c [2] d2 3e [2] d4 0b [2] fa 0b [2] c5 17 }

  condition:
    any of them
}