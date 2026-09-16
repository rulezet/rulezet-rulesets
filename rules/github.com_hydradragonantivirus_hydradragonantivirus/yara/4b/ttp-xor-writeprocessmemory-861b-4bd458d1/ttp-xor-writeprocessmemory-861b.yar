rule TTP_XOR_WriteProcessMemory_861b {
  strings:
    $key_861b = { d1 69 [2] e3 4b [2] e5 7e [2] cb 7e [2] f4 62 }

  condition:
    any of them
}