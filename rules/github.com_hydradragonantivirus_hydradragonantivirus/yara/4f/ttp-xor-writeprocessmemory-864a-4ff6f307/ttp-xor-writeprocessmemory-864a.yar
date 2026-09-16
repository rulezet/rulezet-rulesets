rule TTP_XOR_WriteProcessMemory_864a {
  strings:
    $key_864a = { d1 38 [2] e3 1a [2] e5 2f [2] cb 2f [2] f4 33 }

  condition:
    any of them
}