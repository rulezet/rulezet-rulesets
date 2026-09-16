rule TTP_XOR_WriteProcessMemory_8699 {
  strings:
    $key_8699 = { d1 eb [2] e3 c9 [2] e5 fc [2] cb fc [2] f4 e0 }

  condition:
    any of them
}