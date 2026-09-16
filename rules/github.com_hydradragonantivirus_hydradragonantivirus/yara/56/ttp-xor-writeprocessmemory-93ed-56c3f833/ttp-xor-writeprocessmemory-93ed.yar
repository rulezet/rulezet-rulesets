rule TTP_XOR_WriteProcessMemory_93ed {
  strings:
    $key_93ed = { c4 9f [2] f6 bd [2] f0 88 [2] de 88 [2] e1 94 }

  condition:
    any of them
}