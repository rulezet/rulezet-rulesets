rule TTP_XOR_WriteProcessMemory_b33c {
  strings:
    $key_b33c = { e4 4e [2] d6 6c [2] d0 59 [2] fe 59 [2] c1 45 }

  condition:
    any of them
}