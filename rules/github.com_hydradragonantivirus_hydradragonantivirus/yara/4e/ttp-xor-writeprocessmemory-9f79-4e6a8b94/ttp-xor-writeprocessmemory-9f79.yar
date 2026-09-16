rule TTP_XOR_WriteProcessMemory_9f79 {
  strings:
    $key_9f79 = { c8 0b [2] fa 29 [2] fc 1c [2] d2 1c [2] ed 00 }

  condition:
    any of them
}