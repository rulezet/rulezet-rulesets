rule TTP_XOR_WriteProcessMemory_b13c {
  strings:
    $key_b13c = { e6 4e [2] d4 6c [2] d2 59 [2] fc 59 [2] c3 45 }

  condition:
    any of them
}