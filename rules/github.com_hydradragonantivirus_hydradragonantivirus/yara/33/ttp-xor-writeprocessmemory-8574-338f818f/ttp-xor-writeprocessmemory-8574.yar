rule TTP_XOR_WriteProcessMemory_8574 {
  strings:
    $key_8574 = { d2 06 [2] e0 24 [2] e6 11 [2] c8 11 [2] f7 0d }

  condition:
    any of them
}