rule TTP_XOR_WriteProcessMemory_9f35 {
  strings:
    $key_9f35 = { c8 47 [2] fa 65 [2] fc 50 [2] d2 50 [2] ed 4c }

  condition:
    any of them
}