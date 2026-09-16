rule TTP_XOR_WriteProcessMemory_e53b {
  strings:
    $key_e53b = { b2 49 [2] 80 6b [2] 86 5e [2] a8 5e [2] 97 42 }

  condition:
    any of them
}