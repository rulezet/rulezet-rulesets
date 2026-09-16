rule TTP_XOR_WriteProcessMemory_9f66 {
  strings:
    $key_9f66 = { c8 14 [2] fa 36 [2] fc 03 [2] d2 03 [2] ed 1f }

  condition:
    any of them
}