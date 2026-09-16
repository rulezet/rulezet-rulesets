rule TTP_XOR_WriteProcessMemory_8099 {
  strings:
    $key_8099 = { d7 eb [2] e5 c9 [2] e3 fc [2] cd fc [2] f2 e0 }

  condition:
    any of them
}