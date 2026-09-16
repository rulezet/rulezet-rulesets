rule TTP_XOR_WriteProcessMemory_808e {
  strings:
    $key_808e = { d7 fc [2] e5 de [2] e3 eb [2] cd eb [2] f2 f7 }

  condition:
    any of them
}