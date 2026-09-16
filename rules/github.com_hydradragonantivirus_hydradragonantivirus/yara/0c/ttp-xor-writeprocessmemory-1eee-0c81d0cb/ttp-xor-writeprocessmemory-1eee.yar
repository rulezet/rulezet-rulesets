rule TTP_XOR_WriteProcessMemory_1eee {
  strings:
    $key_1eee = { 49 9c [2] 7b be [2] 7d 8b [2] 53 8b [2] 6c 97 }

  condition:
    any of them
}