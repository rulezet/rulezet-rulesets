rule TTP_XOR_WriteProcessMemory_0aee {
  strings:
    $key_0aee = { 5d 9c [2] 6f be [2] 69 8b [2] 47 8b [2] 78 97 }

  condition:
    any of them
}