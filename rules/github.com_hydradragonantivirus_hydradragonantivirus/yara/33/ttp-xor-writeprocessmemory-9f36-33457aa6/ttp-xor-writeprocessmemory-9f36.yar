rule TTP_XOR_WriteProcessMemory_9f36 {
  strings:
    $key_9f36 = { c8 44 [2] fa 66 [2] fc 53 [2] d2 53 [2] ed 4f }

  condition:
    any of them
}