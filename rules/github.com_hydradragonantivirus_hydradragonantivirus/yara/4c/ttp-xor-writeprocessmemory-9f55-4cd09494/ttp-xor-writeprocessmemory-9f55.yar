rule TTP_XOR_WriteProcessMemory_9f55 {
  strings:
    $key_9f55 = { c8 27 [2] fa 05 [2] fc 30 [2] d2 30 [2] ed 2c }

  condition:
    any of them
}