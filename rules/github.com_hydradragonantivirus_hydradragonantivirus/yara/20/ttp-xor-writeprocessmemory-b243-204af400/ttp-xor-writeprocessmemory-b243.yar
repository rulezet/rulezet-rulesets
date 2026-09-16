rule TTP_XOR_WriteProcessMemory_b243 {
  strings:
    $key_b243 = { e5 31 [2] d7 13 [2] d1 26 [2] ff 26 [2] c0 3a }

  condition:
    any of them
}