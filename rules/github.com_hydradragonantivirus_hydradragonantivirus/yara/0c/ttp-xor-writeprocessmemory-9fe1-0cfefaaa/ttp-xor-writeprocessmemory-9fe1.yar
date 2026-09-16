rule TTP_XOR_WriteProcessMemory_9fe1 {
  strings:
    $key_9fe1 = { c8 93 [2] fa b1 [2] fc 84 [2] d2 84 [2] ed 98 }

  condition:
    any of them
}