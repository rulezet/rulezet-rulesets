rule TTP_XOR_WriteProcessMemory_95c8 {
  strings:
    $key_95c8 = { c2 ba [2] f0 98 [2] f6 ad [2] d8 ad [2] e7 b1 }

  condition:
    any of them
}