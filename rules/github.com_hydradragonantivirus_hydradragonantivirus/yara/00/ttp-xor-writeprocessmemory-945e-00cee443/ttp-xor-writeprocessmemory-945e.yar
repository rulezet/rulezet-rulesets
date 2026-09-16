rule TTP_XOR_WriteProcessMemory_945e {
  strings:
    $key_945e = { c3 2c [2] f1 0e [2] f7 3b [2] d9 3b [2] e6 27 }

  condition:
    any of them
}