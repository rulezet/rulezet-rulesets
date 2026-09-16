rule TTP_XOR_WriteProcessMemory_933a {
  strings:
    $key_933a = { c4 48 [2] f6 6a [2] f0 5f [2] de 5f [2] e1 43 }

  condition:
    any of them
}