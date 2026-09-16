rule TTP_XOR_WriteProcessMemory_925a {
  strings:
    $key_925a = { c5 28 [2] f7 0a [2] f1 3f [2] df 3f [2] e0 23 }

  condition:
    any of them
}