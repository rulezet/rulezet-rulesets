rule TTP_XOR_WriteProcessMemory_866a {
  strings:
    $key_866a = { d1 18 [2] e3 3a [2] e5 0f [2] cb 0f [2] f4 13 }

  condition:
    any of them
}