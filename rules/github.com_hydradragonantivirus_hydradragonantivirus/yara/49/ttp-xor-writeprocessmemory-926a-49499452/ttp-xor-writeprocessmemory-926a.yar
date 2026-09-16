rule TTP_XOR_WriteProcessMemory_926a {
  strings:
    $key_926a = { c5 18 [2] f7 3a [2] f1 0f [2] df 0f [2] e0 13 }

  condition:
    any of them
}