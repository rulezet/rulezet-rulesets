rule TTP_XOR_WriteProcessMemory_8633 {
  strings:
    $key_8633 = { d1 41 [2] e3 63 [2] e5 56 [2] cb 56 [2] f4 4a }

  condition:
    any of them
}