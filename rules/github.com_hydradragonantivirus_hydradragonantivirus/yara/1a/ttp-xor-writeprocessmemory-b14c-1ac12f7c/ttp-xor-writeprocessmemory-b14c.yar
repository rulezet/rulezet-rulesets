rule TTP_XOR_WriteProcessMemory_b14c {
  strings:
    $key_b14c = { e6 3e [2] d4 1c [2] d2 29 [2] fc 29 [2] c3 35 }

  condition:
    any of them
}