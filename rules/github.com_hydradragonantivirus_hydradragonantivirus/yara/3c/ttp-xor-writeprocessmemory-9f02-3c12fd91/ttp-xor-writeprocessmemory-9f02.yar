rule TTP_XOR_WriteProcessMemory_9f02 {
  strings:
    $key_9f02 = { c8 70 [2] fa 52 [2] fc 67 [2] d2 67 [2] ed 7b }

  condition:
    any of them
}