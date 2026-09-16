rule TTP_XOR_WriteProcessMemory_2aee {
  strings:
    $key_2aee = { 7d 9c [2] 4f be [2] 49 8b [2] 67 8b [2] 58 97 }

  condition:
    any of them
}