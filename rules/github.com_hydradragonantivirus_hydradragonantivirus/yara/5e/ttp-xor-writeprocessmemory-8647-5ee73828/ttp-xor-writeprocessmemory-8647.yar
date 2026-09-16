rule TTP_XOR_WriteProcessMemory_8647 {
  strings:
    $key_8647 = { d1 35 [2] e3 17 [2] e5 22 [2] cb 22 [2] f4 3e }

  condition:
    any of them
}