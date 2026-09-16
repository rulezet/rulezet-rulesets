rule TTP_XOR_WriteProcessMemory_932e {
  strings:
    $key_932e = { c4 5c [2] f6 7e [2] f0 4b [2] de 4b [2] e1 57 }

  condition:
    any of them
}