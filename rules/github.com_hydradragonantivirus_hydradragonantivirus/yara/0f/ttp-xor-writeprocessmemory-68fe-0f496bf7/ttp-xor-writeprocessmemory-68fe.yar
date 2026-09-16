rule TTP_XOR_WriteProcessMemory_68fe {
  strings:
    $key_68fe = { 3f 8c [2] 0d ae [2] 0b 9b [2] 25 9b [2] 1a 87 }

  condition:
    any of them
}