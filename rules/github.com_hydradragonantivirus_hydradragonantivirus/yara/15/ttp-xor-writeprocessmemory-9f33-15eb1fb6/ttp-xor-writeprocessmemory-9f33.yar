rule TTP_XOR_WriteProcessMemory_9f33 {
  strings:
    $key_9f33 = { c8 41 [2] fa 63 [2] fc 56 [2] d2 56 [2] ed 4a }

  condition:
    any of them
}