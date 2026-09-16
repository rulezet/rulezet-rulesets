rule TTP_XOR_WriteProcessMemory_b179 {
  strings:
    $key_b179 = { e6 0b [2] d4 29 [2] d2 1c [2] fc 1c [2] c3 00 }

  condition:
    any of them
}