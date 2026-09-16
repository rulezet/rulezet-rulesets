rule TTP_XOR_WriteProcessMemory_dbee {
  strings:
    $key_dbee = { 8c 9c [2] be be [2] b8 8b [2] 96 8b [2] a9 97 }

  condition:
    any of them
}