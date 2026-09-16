rule TTP_XOR_WriteProcessMemory_866e {
  strings:
    $key_866e = { d1 1c [2] e3 3e [2] e5 0b [2] cb 0b [2] f4 17 }

  condition:
    any of them
}