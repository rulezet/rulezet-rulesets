rule TTP_XOR_WriteProcessMemory_93e9 {
  strings:
    $key_93e9 = { c4 9b [2] f6 b9 [2] f0 8c [2] de 8c [2] e1 90 }

  condition:
    any of them
}