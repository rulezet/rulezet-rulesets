rule TTP_XOR_WriteProcessMemory_9f63 {
  strings:
    $key_9f63 = { c8 11 [2] fa 33 [2] fc 06 [2] d2 06 [2] ed 1a }

  condition:
    any of them
}