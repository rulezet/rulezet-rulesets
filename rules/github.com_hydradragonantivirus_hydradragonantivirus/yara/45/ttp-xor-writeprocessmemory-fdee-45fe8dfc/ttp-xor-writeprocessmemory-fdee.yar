rule TTP_XOR_WriteProcessMemory_fdee {
  strings:
    $key_fdee = { aa 9c [2] 98 be [2] 9e 8b [2] b0 8b [2] 8f 97 }

  condition:
    any of them
}