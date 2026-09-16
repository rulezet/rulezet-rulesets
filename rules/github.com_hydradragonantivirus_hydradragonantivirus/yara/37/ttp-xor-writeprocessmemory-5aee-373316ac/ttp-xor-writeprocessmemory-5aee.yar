rule TTP_XOR_WriteProcessMemory_5aee {
  strings:
    $key_5aee = { 0d 9c [2] 3f be [2] 39 8b [2] 17 8b [2] 28 97 }

  condition:
    any of them
}