rule TTP_XOR_WriteProcessMemory_8667 {
  strings:
    $key_8667 = { d1 15 [2] e3 37 [2] e5 02 [2] cb 02 [2] f4 1e }

  condition:
    any of them
}