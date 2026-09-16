rule TTP_XOR_WriteProcessMemory_b72b {
  strings:
    $key_b72b = { e0 59 [2] d2 7b [2] d4 4e [2] fa 4e [2] c5 52 }

  condition:
    any of them
}