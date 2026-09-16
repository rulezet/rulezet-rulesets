rule TTP_XOR_WriteProcessMemory_9edb {
  strings:
    $key_9edb = { c9 a9 [2] fb 8b [2] fd be [2] d3 be [2] ec a2 }

  condition:
    any of them
}