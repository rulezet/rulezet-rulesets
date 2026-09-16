rule TTP_XOR_WriteProcessMemory_9f47 {
  strings:
    $key_9f47 = { c8 35 [2] fa 17 [2] fc 22 [2] d2 22 [2] ed 3e }

  condition:
    any of them
}