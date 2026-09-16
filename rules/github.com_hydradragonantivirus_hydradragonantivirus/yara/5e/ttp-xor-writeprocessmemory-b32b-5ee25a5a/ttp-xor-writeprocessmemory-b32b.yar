rule TTP_XOR_WriteProcessMemory_b32b {
  strings:
    $key_b32b = { e4 59 [2] d6 7b [2] d0 4e [2] fe 4e [2] c1 52 }

  condition:
    any of them
}