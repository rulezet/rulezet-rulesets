rule TTP_XOR_WriteProcessMemory_0e1e {
  strings:
    $key_0e1e = { 59 6c [2] 6b 4e [2] 6d 7b [2] 43 7b [2] 7c 67 }

  condition:
    any of them
}