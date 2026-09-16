rule TTP_XOR_WriteProcessMemory_9099 {
  strings:
    $key_9099 = { c7 eb [2] f5 c9 [2] f3 fc [2] dd fc [2] e2 e0 }

  condition:
    any of them
}