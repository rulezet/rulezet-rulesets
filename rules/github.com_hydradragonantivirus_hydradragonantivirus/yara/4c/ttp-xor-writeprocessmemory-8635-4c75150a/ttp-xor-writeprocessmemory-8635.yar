rule TTP_XOR_WriteProcessMemory_8635 {
  strings:
    $key_8635 = { d1 47 [2] e3 65 [2] e5 50 [2] cb 50 [2] f4 4c }

  condition:
    any of them
}