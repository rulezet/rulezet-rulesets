rule TTP_XOR_WriteProcessMemory_874a {
  strings:
    $key_874a = { d0 38 [2] e2 1a [2] e4 2f [2] ca 2f [2] f5 33 }

  condition:
    any of them
}