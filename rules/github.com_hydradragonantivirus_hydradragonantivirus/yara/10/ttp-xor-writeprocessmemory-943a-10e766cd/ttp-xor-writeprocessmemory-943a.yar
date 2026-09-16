rule TTP_XOR_WriteProcessMemory_943a {
  strings:
    $key_943a = { c3 48 [2] f1 6a [2] f7 5f [2] d9 5f [2] e6 43 }

  condition:
    any of them
}