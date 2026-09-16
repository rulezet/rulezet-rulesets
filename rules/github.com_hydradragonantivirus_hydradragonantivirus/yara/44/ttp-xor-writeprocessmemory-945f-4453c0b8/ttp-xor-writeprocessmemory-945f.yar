rule TTP_XOR_WriteProcessMemory_945f {
  strings:
    $key_945f = { c3 2d [2] f1 0f [2] f7 3a [2] d9 3a [2] e6 26 }

  condition:
    any of them
}