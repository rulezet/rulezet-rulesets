rule TTP_XOR_WriteProcessMemory_b1f9 {
  strings:
    $key_b1f9 = { e6 8b [2] d4 a9 [2] d2 9c [2] fc 9c [2] c3 80 }

  condition:
    any of them
}