rule TTP_XOR_WriteProcessMemory_39fe {
  strings:
    $key_39fe = { 6e 8c [2] 5c ae [2] 5a 9b [2] 74 9b [2] 4b 87 }

  condition:
    any of them
}