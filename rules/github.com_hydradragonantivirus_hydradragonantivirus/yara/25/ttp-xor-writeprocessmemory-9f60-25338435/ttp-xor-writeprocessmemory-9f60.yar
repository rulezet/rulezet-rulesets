rule TTP_XOR_WriteProcessMemory_9f60 {
  strings:
    $key_9f60 = { c8 12 [2] fa 30 [2] fc 05 [2] d2 05 [2] ed 19 }

  condition:
    any of them
}