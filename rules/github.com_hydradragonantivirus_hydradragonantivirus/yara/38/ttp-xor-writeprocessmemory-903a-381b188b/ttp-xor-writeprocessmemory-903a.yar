rule TTP_XOR_WriteProcessMemory_903a {
  strings:
    $key_903a = { c7 48 [2] f5 6a [2] f3 5f [2] dd 5f [2] e2 43 }

  condition:
    any of them
}