rule TTP_XOR_WriteProcessMemory_93fd {
  strings:
    $key_93fd = { c4 8f [2] f6 ad [2] f0 98 [2] de 98 [2] e1 84 }

  condition:
    any of them
}