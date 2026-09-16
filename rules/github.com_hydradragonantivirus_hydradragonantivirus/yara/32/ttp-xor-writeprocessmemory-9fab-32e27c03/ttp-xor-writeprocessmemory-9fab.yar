rule TTP_XOR_WriteProcessMemory_9fab {
  strings:
    $key_9fab = { c8 d9 [2] fa fb [2] fc ce [2] d2 ce [2] ed d2 }

  condition:
    any of them
}