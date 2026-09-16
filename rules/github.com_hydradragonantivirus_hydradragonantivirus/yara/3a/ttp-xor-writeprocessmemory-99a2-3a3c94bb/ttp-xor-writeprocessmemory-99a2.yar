rule TTP_XOR_WriteProcessMemory_99a2 {
  strings:
    $key_99a2 = { ce d0 [2] fc f2 [2] fa c7 [2] d4 c7 [2] eb db }

  condition:
    any of them
}