rule TTP_XOR_WriteProcessMemory_3cee {
  strings:
    $key_3cee = { 6b 9c [2] 59 be [2] 5f 8b [2] 71 8b [2] 4e 97 }

  condition:
    any of them
}