rule TTP_XOR_WriteProcessMemory_931e {
  strings:
    $key_931e = { c4 6c [2] f6 4e [2] f0 7b [2] de 7b [2] e1 67 }

  condition:
    any of them
}