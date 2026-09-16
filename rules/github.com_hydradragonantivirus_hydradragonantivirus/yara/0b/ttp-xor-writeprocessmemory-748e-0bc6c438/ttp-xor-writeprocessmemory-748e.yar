rule TTP_XOR_WriteProcessMemory_748e {
  strings:
    $key_748e = { 23 fc [2] 11 de [2] 17 eb [2] 39 eb [2] 06 f7 }

  condition:
    any of them
}