rule TTP_XOR_WriteProcessMemory_feec {
  strings:
    $key_feec = { a9 9e [2] 9b bc [2] 9d 89 [2] b3 89 [2] 8c 95 }

  condition:
    any of them
}