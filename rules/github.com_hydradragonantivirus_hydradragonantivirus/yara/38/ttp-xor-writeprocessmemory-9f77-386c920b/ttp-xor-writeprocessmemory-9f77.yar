rule TTP_XOR_WriteProcessMemory_9f77 {
  strings:
    $key_9f77 = { c8 05 [2] fa 27 [2] fc 12 [2] d2 12 [2] ed 0e }

  condition:
    any of them
}