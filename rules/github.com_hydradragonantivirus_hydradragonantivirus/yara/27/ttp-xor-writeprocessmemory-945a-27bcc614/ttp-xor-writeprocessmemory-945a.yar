rule TTP_XOR_WriteProcessMemory_945a {
  strings:
    $key_945a = { c3 28 [2] f1 0a [2] f7 3f [2] d9 3f [2] e6 23 }

  condition:
    any of them
}