rule TTP_XOR_WriteProcessMemory_9ff6 {
  strings:
    $key_9ff6 = { c8 84 [2] fa a6 [2] fc 93 [2] d2 93 [2] ed 8f }

  condition:
    any of them
}