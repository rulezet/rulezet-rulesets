rule TTP_XOR_WriteProcessMemory_b53b {
  strings:
    $key_b53b = { e2 49 [2] d0 6b [2] d6 5e [2] f8 5e [2] c7 42 }

  condition:
    any of them
}