rule TTP_XOR_WriteProcessMemory_9f45 {
  strings:
    $key_9f45 = { c8 37 [2] fa 15 [2] fc 20 [2] d2 20 [2] ed 3c }

  condition:
    any of them
}