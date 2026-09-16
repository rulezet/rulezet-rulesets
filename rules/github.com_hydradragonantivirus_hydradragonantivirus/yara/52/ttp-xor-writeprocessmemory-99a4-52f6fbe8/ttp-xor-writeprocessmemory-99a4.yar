rule TTP_XOR_WriteProcessMemory_99a4 {
  strings:
    $key_99a4 = { ce d6 [2] fc f4 [2] fa c1 [2] d4 c1 [2] eb dd }

  condition:
    any of them
}