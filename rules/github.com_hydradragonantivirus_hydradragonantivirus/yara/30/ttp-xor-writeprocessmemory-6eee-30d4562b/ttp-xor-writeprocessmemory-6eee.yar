rule TTP_XOR_WriteProcessMemory_6eee {
  strings:
    $key_6eee = { 39 9c [2] 0b be [2] 0d 8b [2] 23 8b [2] 1c 97 }

  condition:
    any of them
}