rule TTP_XOR_WriteProcessMemory_9f69 {
  strings:
    $key_9f69 = { c8 1b [2] fa 39 [2] fc 0c [2] d2 0c [2] ed 10 }

  condition:
    any of them
}