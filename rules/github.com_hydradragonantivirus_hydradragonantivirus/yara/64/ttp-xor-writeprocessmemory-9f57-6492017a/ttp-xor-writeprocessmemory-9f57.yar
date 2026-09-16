rule TTP_XOR_WriteProcessMemory_9f57 {
  strings:
    $key_9f57 = { c8 25 [2] fa 07 [2] fc 32 [2] d2 32 [2] ed 2e }

  condition:
    any of them
}