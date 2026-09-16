rule TTP_XOR_WriteProcessMemory_9f27 {
  strings:
    $key_9f27 = { c8 55 [2] fa 77 [2] fc 42 [2] d2 42 [2] ed 5e }

  condition:
    any of them
}