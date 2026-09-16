rule TTP_XOR_WriteProcessMemory_b2f3 {
  strings:
    $key_b2f3 = { e5 81 [2] d7 a3 [2] d1 96 [2] ff 96 [2] c0 8a }

  condition:
    any of them
}