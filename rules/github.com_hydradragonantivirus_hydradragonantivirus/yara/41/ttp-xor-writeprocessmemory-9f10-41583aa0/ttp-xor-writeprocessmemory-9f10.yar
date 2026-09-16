rule TTP_XOR_WriteProcessMemory_9f10 {
  strings:
    $key_9f10 = { c8 62 [2] fa 40 [2] fc 75 [2] d2 75 [2] ed 69 }

  condition:
    any of them
}