rule TTP_XOR_WriteProcessMemory_9ffe {
  strings:
    $key_9ffe = { c8 8c [2] fa ae [2] fc 9b [2] d2 9b [2] ed 87 }

  condition:
    any of them
}