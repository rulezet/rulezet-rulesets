rule TTP_XOR_WriteProcessMemory_875a {
  strings:
    $key_875a = { d0 28 [2] e2 0a [2] e4 3f [2] ca 3f [2] f5 23 }

  condition:
    any of them
}