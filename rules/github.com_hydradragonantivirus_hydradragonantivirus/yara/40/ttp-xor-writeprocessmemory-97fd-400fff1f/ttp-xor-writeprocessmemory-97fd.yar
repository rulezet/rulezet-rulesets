rule TTP_XOR_WriteProcessMemory_97fd {
  strings:
    $key_97fd = { c0 8f [2] f2 ad [2] f4 98 [2] da 98 [2] e5 84 }

  condition:
    any of them
}