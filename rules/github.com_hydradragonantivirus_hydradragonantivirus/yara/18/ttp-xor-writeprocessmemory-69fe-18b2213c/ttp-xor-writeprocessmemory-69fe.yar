rule TTP_XOR_WriteProcessMemory_69fe {
  strings:
    $key_69fe = { 3e 8c [2] 0c ae [2] 0a 9b [2] 24 9b [2] 1b 87 }

  condition:
    any of them
}