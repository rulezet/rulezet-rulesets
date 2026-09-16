rule TTP_XOR_WriteProcessMemory_99a6 {
  strings:
    $key_99a6 = { ce d4 [2] fc f6 [2] fa c3 [2] d4 c3 [2] eb df }

  condition:
    any of them
}