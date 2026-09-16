rule TTP_XOR_WriteProcessMemory_feee {
  strings:
    $key_feee = { a9 9c [2] 9b be [2] 9d 8b [2] b3 8b [2] 8c 97 }

  condition:
    any of them
}