rule TTP_XOR_WriteProcessMemory_e9fe {
  strings:
    $key_e9fe = { be 8c [2] 8c ae [2] 8a 9b [2] a4 9b [2] 9b 87 }

  condition:
    any of them
}