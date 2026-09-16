rule TTP_XOR_WriteProcessMemory_08fe {
  strings:
    $key_08fe = { 5f 8c [2] 6d ae [2] 6b 9b [2] 45 9b [2] 7a 87 }

  condition:
    any of them
}