rule TTP_XOR_WriteProcessMemory_bf8e {
  strings:
    $key_bf8e = { e8 fc [2] da de [2] dc eb [2] f2 eb [2] cd f7 }

  condition:
    any of them
}