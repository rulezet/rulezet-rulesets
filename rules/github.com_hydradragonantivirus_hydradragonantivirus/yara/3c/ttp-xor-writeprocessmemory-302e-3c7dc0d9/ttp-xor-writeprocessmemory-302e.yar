rule TTP_XOR_WriteProcessMemory_302e {
  strings:
    $key_302e = { 67 5c [2] 55 7e [2] 53 4b [2] 7d 4b [2] 42 57 }

  condition:
    any of them
}