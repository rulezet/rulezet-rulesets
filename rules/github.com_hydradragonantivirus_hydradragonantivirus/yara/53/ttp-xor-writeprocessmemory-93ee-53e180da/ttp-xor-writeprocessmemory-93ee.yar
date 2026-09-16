rule TTP_XOR_WriteProcessMemory_93ee {
  strings:
    $key_93ee = { c4 9c [2] f6 be [2] f0 8b [2] de 8b [2] e1 97 }

  condition:
    any of them
}