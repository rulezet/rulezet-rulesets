rule TTP_XOR_WriteProcessMemory_b1c3 {
  strings:
    $key_b1c3 = { e6 b1 [2] d4 93 [2] d2 a6 [2] fc a6 [2] c3 ba }

  condition:
    any of them
}