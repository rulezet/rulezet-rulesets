rule TTP_XOR_WriteProcessMemory_860a {
  strings:
    $key_860a = { d1 78 [2] e3 5a [2] e5 6f [2] cb 6f [2] f4 73 }

  condition:
    any of them
}