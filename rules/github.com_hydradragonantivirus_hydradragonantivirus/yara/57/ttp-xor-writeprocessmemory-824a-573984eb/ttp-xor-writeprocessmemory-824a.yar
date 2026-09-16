rule TTP_XOR_WriteProcessMemory_824a {
  strings:
    $key_824a = { d5 38 [2] e7 1a [2] e1 2f [2] cf 2f [2] f0 33 }

  condition:
    any of them
}