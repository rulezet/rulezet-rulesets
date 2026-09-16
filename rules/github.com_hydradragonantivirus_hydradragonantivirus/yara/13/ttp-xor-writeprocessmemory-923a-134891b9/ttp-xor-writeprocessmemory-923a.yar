rule TTP_XOR_WriteProcessMemory_923a {
  strings:
    $key_923a = { c5 48 [2] f7 6a [2] f1 5f [2] df 5f [2] e0 43 }

  condition:
    any of them
}