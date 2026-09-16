rule TTP_XOR_WriteProcessMemory_99c6 {
  strings:
    $key_99c6 = { ce b4 [2] fc 96 [2] fa a3 [2] d4 a3 [2] eb bf }

  condition:
    any of them
}