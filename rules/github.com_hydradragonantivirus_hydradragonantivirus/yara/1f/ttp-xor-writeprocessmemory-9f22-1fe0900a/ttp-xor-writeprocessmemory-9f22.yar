rule TTP_XOR_WriteProcessMemory_9f22 {
  strings:
    $key_9f22 = { c8 50 [2] fa 72 [2] fc 47 [2] d2 47 [2] ed 5b }

  condition:
    any of them
}