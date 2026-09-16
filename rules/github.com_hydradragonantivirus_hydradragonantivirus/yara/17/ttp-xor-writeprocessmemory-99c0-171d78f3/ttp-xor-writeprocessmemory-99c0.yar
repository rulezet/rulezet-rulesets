rule TTP_XOR_WriteProcessMemory_99c0 {
  strings:
    $key_99c0 = { ce b2 [2] fc 90 [2] fa a5 [2] d4 a5 [2] eb b9 }

  condition:
    any of them
}