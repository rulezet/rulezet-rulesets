rule TTP_XOR_WriteProcessMemory_9ff2 {
  strings:
    $key_9ff2 = { c8 80 [2] fa a2 [2] fc 97 [2] d2 97 [2] ed 8b }

  condition:
    any of them
}