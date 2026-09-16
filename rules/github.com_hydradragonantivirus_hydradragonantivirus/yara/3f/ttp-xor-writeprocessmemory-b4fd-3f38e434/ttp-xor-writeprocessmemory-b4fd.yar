rule TTP_XOR_WriteProcessMemory_b4fd {
  strings:
    $key_b4fd = { e3 8f [2] d1 ad [2] d7 98 [2] f9 98 [2] c6 84 }

  condition:
    any of them
}