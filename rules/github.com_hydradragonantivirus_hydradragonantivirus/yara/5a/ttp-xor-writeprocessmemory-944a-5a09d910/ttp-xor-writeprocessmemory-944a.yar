rule TTP_XOR_WriteProcessMemory_944a {
  strings:
    $key_944a = { c3 38 [2] f1 1a [2] f7 2f [2] d9 2f [2] e6 33 }

  condition:
    any of them
}