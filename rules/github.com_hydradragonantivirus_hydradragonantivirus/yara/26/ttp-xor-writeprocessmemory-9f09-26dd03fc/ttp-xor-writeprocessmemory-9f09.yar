rule TTP_XOR_WriteProcessMemory_9f09 {
  strings:
    $key_9f09 = { c8 7b [2] fa 59 [2] fc 6c [2] d2 6c [2] ed 70 }

  condition:
    any of them
}