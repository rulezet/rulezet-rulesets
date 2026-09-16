rule TTP_XOR_WriteProcessMemory_b71b {
  strings:
    $key_b71b = { e0 69 [2] d2 4b [2] d4 7e [2] fa 7e [2] c5 62 }

  condition:
    any of them
}