rule TTP_XOR_WriteProcessMemory_93fa {
  strings:
    $key_93fa = { c4 88 [2] f6 aa [2] f0 9f [2] de 9f [2] e1 83 }

  condition:
    any of them
}