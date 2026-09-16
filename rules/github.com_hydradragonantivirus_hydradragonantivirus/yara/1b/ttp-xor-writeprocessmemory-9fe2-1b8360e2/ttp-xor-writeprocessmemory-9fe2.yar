rule TTP_XOR_WriteProcessMemory_9fe2 {
  strings:
    $key_9fe2 = { c8 90 [2] fa b2 [2] fc 87 [2] d2 87 [2] ed 9b }

  condition:
    any of them
}