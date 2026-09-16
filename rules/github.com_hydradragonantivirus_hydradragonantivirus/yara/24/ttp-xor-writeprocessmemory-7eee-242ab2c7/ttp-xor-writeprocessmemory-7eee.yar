rule TTP_XOR_WriteProcessMemory_7eee {
  strings:
    $key_7eee = { 29 9c [2] 1b be [2] 1d 8b [2] 33 8b [2] 0c 97 }

  condition:
    any of them
}