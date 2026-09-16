rule TTP_XOR_WriteProcessMemory_8617 {
  strings:
    $key_8617 = { d1 65 [2] e3 47 [2] e5 72 [2] cb 72 [2] f4 6e }

  condition:
    any of them
}