rule TTP_XOR_WriteProcessMemory_9f50 {
  strings:
    $key_9f50 = { c8 22 [2] fa 00 [2] fc 35 [2] d2 35 [2] ed 29 }

  condition:
    any of them
}