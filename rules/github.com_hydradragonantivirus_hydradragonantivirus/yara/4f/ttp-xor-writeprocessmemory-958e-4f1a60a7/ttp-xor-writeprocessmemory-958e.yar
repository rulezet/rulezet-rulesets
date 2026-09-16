rule TTP_XOR_WriteProcessMemory_958e {
  strings:
    $key_958e = { c2 fc [2] f0 de [2] f6 eb [2] d8 eb [2] e7 f7 }

  condition:
    any of them
}