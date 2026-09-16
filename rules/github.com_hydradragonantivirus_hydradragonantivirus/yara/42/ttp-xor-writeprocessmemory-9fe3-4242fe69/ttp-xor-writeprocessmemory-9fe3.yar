rule TTP_XOR_WriteProcessMemory_9fe3 {
  strings:
    $key_9fe3 = { c8 91 [2] fa b3 [2] fc 86 [2] d2 86 [2] ed 9a }

  condition:
    any of them
}