rule TTP_XOR_WriteProcessMemory_9f40 {
  strings:
    $key_9f40 = { c8 32 [2] fa 10 [2] fc 25 [2] d2 25 [2] ed 39 }

  condition:
    any of them
}