rule TTP_XOR_WriteProcessMemory_99a9 {
  strings:
    $key_99a9 = { ce db [2] fc f9 [2] fa cc [2] d4 cc [2] eb d0 }

  condition:
    any of them
}