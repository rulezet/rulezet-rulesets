rule TTP_XOR_WriteProcessMemory_b402 {
  strings:
    $key_b402 = { e3 70 [2] d1 52 [2] d7 67 [2] f9 67 [2] c6 7b }

  condition:
    any of them
}