rule TTP_XOR_WriteProcessMemory_4cee {
  strings:
    $key_4cee = { 1b 9c [2] 29 be [2] 2f 8b [2] 01 8b [2] 3e 97 }

  condition:
    any of them
}