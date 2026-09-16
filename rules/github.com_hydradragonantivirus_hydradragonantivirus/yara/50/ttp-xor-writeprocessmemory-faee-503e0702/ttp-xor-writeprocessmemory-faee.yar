rule TTP_XOR_WriteProcessMemory_faee {
  strings:
    $key_faee = { ad 9c [2] 9f be [2] 99 8b [2] b7 8b [2] 88 97 }

  condition:
    any of them
}