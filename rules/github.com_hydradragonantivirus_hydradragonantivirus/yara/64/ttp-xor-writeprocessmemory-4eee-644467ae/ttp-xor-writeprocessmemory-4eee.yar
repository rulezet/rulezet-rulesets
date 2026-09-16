rule TTP_XOR_WriteProcessMemory_4eee {
  strings:
    $key_4eee = { 19 9c [2] 2b be [2] 2d 8b [2] 03 8b [2] 3c 97 }

  condition:
    any of them
}