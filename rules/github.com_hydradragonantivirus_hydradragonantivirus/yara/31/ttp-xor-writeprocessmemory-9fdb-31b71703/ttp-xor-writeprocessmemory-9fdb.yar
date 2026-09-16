rule TTP_XOR_WriteProcessMemory_9fdb {
  strings:
    $key_9fdb = { c8 a9 [2] fa 8b [2] fc be [2] d2 be [2] ed a2 }

  condition:
    any of them
}