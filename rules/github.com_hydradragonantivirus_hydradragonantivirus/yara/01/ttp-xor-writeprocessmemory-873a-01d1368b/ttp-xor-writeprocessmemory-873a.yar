rule TTP_XOR_WriteProcessMemory_873a {
  strings:
    $key_873a = { d0 48 [2] e2 6a [2] e4 5f [2] ca 5f [2] f5 43 }

  condition:
    any of them
}