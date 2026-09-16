rule TTP_XOR_WriteProcessMemory_95fd {
  strings:
    $key_95fd = { c2 8f [2] f0 ad [2] f6 98 [2] d8 98 [2] e7 84 }

  condition:
    any of them
}