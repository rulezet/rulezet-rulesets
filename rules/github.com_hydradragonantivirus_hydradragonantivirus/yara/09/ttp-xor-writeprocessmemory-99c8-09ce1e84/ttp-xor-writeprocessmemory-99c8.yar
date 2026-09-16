rule TTP_XOR_WriteProcessMemory_99c8 {
  strings:
    $key_99c8 = { ce ba [2] fc 98 [2] fa ad [2] d4 ad [2] eb b1 }

  condition:
    any of them
}