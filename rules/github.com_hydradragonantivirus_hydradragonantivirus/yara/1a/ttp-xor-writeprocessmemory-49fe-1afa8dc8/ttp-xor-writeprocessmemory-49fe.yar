rule TTP_XOR_WriteProcessMemory_49fe {
  strings:
    $key_49fe = { 1e 8c [2] 2c ae [2] 2a 9b [2] 04 9b [2] 3b 87 }

  condition:
    any of them
}