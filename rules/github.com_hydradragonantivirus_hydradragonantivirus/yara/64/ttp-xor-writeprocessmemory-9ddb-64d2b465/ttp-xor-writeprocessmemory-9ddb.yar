rule TTP_XOR_WriteProcessMemory_9ddb {
  strings:
    $key_9ddb = { ca a9 [2] f8 8b [2] fe be [2] d0 be [2] ef a2 }

  condition:
    any of them
}