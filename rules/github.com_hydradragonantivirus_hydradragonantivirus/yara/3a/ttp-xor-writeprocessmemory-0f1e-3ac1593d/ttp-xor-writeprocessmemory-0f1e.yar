rule TTP_XOR_WriteProcessMemory_0f1e {
  strings:
    $key_0f1e = { 58 6c [2] 6a 4e [2] 6c 7b [2] 42 7b [2] 7d 67 }

  condition:
    any of them
}