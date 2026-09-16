rule TTP_XOR_WriteProcessMemory_fbdb {
  strings:
    $key_fbdb = { ac a9 [2] 9e 8b [2] 98 be [2] b6 be [2] 89 a2 }

  condition:
    any of them
}