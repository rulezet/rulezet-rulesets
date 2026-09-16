rule TTP_XOR_WriteProcessMemory_8615 {
  strings:
    $key_8615 = { d1 67 [2] e3 45 [2] e5 70 [2] cb 70 [2] f4 6c }

  condition:
    any of them
}