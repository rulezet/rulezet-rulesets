rule TTP_XOR_WriteProcessMemory_9f16 {
  strings:
    $key_9f16 = { c8 64 [2] fa 46 [2] fc 73 [2] d2 73 [2] ed 6f }

  condition:
    any of them
}