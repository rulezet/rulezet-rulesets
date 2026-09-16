rule TTP_XOR_WriteProcessMemory_924a {
  strings:
    $key_924a = { c5 38 [2] f7 1a [2] f1 2f [2] df 2f [2] e0 33 }

  condition:
    any of them
}