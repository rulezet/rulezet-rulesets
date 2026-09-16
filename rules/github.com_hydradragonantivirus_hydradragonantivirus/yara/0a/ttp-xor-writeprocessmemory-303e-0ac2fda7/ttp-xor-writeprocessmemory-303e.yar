rule TTP_XOR_WriteProcessMemory_303e {
  strings:
    $key_303e = { 67 4c [2] 55 6e [2] 53 5b [2] 7d 5b [2] 42 47 }

  condition:
    any of them
}