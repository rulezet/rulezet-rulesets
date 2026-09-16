rule TTP_XOR_WriteProcessMemory_18fe {
  strings:
    $key_18fe = { 4f 8c [2] 7d ae [2] 7b 9b [2] 55 9b [2] 6a 87 }

  condition:
    any of them
}