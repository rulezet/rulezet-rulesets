rule TTP_XOR_WriteProcessMemory_29fe {
  strings:
    $key_29fe = { 7e 8c [2] 4c ae [2] 4a 9b [2] 64 9b [2] 5b 87 }

  condition:
    any of them
}