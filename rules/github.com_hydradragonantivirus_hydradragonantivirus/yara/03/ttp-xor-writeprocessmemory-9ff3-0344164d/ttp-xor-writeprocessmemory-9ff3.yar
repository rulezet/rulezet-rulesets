rule TTP_XOR_WriteProcessMemory_9ff3 {
  strings:
    $key_9ff3 = { c8 81 [2] fa a3 [2] fc 96 [2] d2 96 [2] ed 8a }

  condition:
    any of them
}