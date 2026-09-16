rule TTP_XOR_WriteProcessMemory_b177 {
  strings:
    $key_b177 = { e6 05 [2] d4 27 [2] d2 12 [2] fc 12 [2] c3 0e }

  condition:
    any of them
}