rule TTP_XOR_WriteProcessMemory_9f12 {
  strings:
    $key_9f12 = { c8 60 [2] fa 42 [2] fc 77 [2] d2 77 [2] ed 6b }

  condition:
    any of them
}