rule TTP_XOR_WriteProcessMemory_99d8 {
  strings:
    $key_99d8 = { ce aa [2] fc 88 [2] fa bd [2] d4 bd [2] eb a1 }

  condition:
    any of them
}