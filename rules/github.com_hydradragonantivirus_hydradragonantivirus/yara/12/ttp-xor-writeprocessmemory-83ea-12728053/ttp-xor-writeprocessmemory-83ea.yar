rule TTP_XOR_WriteProcessMemory_83ea {
  strings:
    $key_83ea = { d4 98 [2] e6 ba [2] e0 8f [2] ce 8f [2] f1 93 }

  condition:
    any of them
}