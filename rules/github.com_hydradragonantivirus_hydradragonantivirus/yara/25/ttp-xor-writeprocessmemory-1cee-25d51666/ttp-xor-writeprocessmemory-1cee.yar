rule TTP_XOR_WriteProcessMemory_1cee {
  strings:
    $key_1cee = { 4b 9c [2] 79 be [2] 7f 8b [2] 51 8b [2] 6e 97 }

  condition:
    any of them
}