rule TTP_XOR_WriteProcessMemory_8dc8 {
  strings:
    $key_8dc8 = { da ba [2] e8 98 [2] ee ad [2] c0 ad [2] ff b1 }

  condition:
    any of them
}