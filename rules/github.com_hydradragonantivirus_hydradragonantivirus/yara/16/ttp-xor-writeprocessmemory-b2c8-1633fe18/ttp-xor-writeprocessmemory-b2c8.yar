rule TTP_XOR_WriteProcessMemory_b2c8 {
  strings:
    $key_b2c8 = { e5 ba [2] d7 98 [2] d1 ad [2] ff ad [2] c0 b1 }

  condition:
    any of them
}