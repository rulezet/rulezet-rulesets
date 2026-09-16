rule TTP_XOR_WriteProcessMemory_9f20 {
  strings:
    $key_9f20 = { c8 52 [2] fa 70 [2] fc 45 [2] d2 45 [2] ed 59 }

  condition:
    any of them
}