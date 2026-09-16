rule TTP_XOR_WriteProcessMemory_9f06 {
  strings:
    $key_9f06 = { c8 74 [2] fa 56 [2] fc 63 [2] d2 63 [2] ed 7f }

  condition:
    any of them
}