rule TTP_XOR_WriteProcessMemory_9f53 {
  strings:
    $key_9f53 = { c8 21 [2] fa 03 [2] fc 36 [2] d2 36 [2] ed 2a }

  condition:
    any of them
}