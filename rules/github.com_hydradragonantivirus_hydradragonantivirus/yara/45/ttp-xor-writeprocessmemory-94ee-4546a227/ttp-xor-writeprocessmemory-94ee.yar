rule TTP_XOR_WriteProcessMemory_94ee {
  strings:
    $key_94ee = { c3 9c [2] f1 be [2] f7 8b [2] d9 8b [2] e6 97 }

  condition:
    any of them
}