rule TTP_XOR_WriteProcessMemory_b102 {
  strings:
    $key_b102 = { e6 70 [2] d4 52 [2] d2 67 [2] fc 67 [2] c3 7b }

  condition:
    any of them
}