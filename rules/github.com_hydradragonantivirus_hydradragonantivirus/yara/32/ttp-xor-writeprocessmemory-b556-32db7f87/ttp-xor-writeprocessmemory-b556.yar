rule TTP_XOR_WriteProcessMemory_b556 {
  strings:
    $key_b556 = { e2 24 [2] d0 06 [2] d6 33 [2] f8 33 [2] c7 2f }

  condition:
    any of them
}