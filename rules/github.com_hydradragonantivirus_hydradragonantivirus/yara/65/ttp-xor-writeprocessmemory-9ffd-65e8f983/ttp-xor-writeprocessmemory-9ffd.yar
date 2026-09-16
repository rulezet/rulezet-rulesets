rule TTP_XOR_WriteProcessMemory_9ffd {
  strings:
    $key_9ffd = { c8 8f [2] fa ad [2] fc 98 [2] d2 98 [2] ed 84 }

  condition:
    any of them
}