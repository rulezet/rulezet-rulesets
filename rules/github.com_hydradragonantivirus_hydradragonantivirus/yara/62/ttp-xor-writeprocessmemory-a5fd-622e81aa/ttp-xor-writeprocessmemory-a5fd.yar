rule TTP_XOR_WriteProcessMemory_a5fd {
  strings:
    $key_a5fd = { f2 8f [2] c0 ad [2] c6 98 [2] e8 98 [2] d7 84 }

  condition:
    any of them
}