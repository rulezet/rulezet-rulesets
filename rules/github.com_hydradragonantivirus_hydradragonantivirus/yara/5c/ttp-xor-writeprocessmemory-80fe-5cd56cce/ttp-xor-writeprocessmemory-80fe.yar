rule TTP_XOR_WriteProcessMemory_80fe {
  strings:
    $key_80fe = { d7 8c [2] e5 ae [2] e3 9b [2] cd 9b [2] f2 87 }

  condition:
    any of them
}