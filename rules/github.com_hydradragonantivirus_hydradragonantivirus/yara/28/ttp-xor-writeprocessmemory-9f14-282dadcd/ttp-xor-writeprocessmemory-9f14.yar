rule TTP_XOR_WriteProcessMemory_9f14 {
  strings:
    $key_9f14 = { c8 66 [2] fa 44 [2] fc 71 [2] d2 71 [2] ed 6d }

  condition:
    any of them
}