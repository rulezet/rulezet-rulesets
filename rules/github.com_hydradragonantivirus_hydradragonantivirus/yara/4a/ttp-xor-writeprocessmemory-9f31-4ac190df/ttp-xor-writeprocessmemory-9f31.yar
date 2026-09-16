rule TTP_XOR_WriteProcessMemory_9f31 {
  strings:
    $key_9f31 = { c8 43 [2] fa 61 [2] fc 54 [2] d2 54 [2] ed 48 }

  condition:
    any of them
}