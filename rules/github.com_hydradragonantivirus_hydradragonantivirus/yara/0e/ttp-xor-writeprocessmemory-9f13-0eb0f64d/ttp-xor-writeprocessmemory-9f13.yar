rule TTP_XOR_WriteProcessMemory_9f13 {
  strings:
    $key_9f13 = { c8 61 [2] fa 43 [2] fc 76 [2] d2 76 [2] ed 6a }

  condition:
    any of them
}