rule TTP_XOR_WriteProcessMemory_b7fd {
  strings:
    $key_b7fd = { e0 8f [2] d2 ad [2] d4 98 [2] fa 98 [2] c5 84 }

  condition:
    any of them
}