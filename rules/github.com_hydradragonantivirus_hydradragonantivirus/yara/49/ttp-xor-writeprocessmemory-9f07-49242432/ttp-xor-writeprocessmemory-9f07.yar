rule TTP_XOR_WriteProcessMemory_9f07 {
  strings:
    $key_9f07 = { c8 75 [2] fa 57 [2] fc 62 [2] d2 62 [2] ed 7e }

  condition:
    any of them
}