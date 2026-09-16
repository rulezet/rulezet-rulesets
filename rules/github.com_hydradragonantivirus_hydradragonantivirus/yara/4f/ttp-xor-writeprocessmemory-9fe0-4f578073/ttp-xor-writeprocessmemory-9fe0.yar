rule TTP_XOR_WriteProcessMemory_9fe0 {
  strings:
    $key_9fe0 = { c8 92 [2] fa b0 [2] fc 85 [2] d2 85 [2] ed 99 }

  condition:
    any of them
}