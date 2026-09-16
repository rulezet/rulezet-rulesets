rule TTP_XOR_WriteProcessMemory_945d {
  strings:
    $key_945d = { c3 2f [2] f1 0d [2] f7 38 [2] d9 38 [2] e6 24 }

  condition:
    any of them
}