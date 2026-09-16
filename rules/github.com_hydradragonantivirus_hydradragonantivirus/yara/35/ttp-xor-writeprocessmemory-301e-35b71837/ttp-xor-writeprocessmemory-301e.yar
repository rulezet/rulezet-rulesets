rule TTP_XOR_WriteProcessMemory_301e {
  strings:
    $key_301e = { 67 6c [2] 55 4e [2] 53 7b [2] 7d 7b [2] 42 67 }

  condition:
    any of them
}