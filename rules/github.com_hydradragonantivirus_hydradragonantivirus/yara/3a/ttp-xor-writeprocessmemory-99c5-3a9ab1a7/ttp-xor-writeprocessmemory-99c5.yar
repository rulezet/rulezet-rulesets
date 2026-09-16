rule TTP_XOR_WriteProcessMemory_99c5 {
  strings:
    $key_99c5 = { ce b7 [2] fc 95 [2] fa a0 [2] d4 a0 [2] eb bc }

  condition:
    any of them
}