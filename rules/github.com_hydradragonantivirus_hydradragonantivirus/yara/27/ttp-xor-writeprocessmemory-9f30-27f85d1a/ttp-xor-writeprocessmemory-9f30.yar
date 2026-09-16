rule TTP_XOR_WriteProcessMemory_9f30 {
  strings:
    $key_9f30 = { c8 42 [2] fa 60 [2] fc 55 [2] d2 55 [2] ed 49 }

  condition:
    any of them
}