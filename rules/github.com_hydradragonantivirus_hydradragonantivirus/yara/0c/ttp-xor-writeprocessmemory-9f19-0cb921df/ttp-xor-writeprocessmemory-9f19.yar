rule TTP_XOR_WriteProcessMemory_9f19 {
  strings:
    $key_9f19 = { c8 6b [2] fa 49 [2] fc 7c [2] d2 7c [2] ed 60 }

  condition:
    any of them
}