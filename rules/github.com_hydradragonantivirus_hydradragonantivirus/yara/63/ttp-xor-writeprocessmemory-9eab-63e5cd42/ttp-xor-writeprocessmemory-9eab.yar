rule TTP_XOR_WriteProcessMemory_9eab {
  strings:
    $key_9eab = { c9 d9 [2] fb fb [2] fd ce [2] d3 ce [2] ec d2 }

  condition:
    any of them
}