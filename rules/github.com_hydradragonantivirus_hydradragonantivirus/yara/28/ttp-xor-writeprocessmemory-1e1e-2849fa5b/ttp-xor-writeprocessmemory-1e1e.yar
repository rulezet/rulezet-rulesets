rule TTP_XOR_WriteProcessMemory_1e1e {
  strings:
    $key_1e1e = { 49 6c [2] 7b 4e [2] 7d 7b [2] 53 7b [2] 6c 67 }

  condition:
    any of them
}