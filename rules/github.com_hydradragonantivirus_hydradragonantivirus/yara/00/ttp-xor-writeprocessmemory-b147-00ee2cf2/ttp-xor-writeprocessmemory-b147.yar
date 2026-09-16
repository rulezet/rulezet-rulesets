rule TTP_XOR_WriteProcessMemory_b147 {
  strings:
    $key_b147 = { e6 35 [2] d4 17 [2] d2 22 [2] fc 22 [2] c3 3e }

  condition:
    any of them
}