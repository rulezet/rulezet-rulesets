rule TTP_XOR_WriteProcessMemory_99a5 {
  strings:
    $key_99a5 = { ce d7 [2] fc f5 [2] fa c0 [2] d4 c0 [2] eb dc }

  condition:
    any of them
}