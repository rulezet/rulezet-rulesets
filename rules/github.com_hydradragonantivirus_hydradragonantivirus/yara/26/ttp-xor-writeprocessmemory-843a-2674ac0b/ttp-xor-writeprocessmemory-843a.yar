rule TTP_XOR_WriteProcessMemory_843a {
  strings:
    $key_843a = { d3 48 [2] e1 6a [2] e7 5f [2] c9 5f [2] f6 43 }

  condition:
    any of them
}