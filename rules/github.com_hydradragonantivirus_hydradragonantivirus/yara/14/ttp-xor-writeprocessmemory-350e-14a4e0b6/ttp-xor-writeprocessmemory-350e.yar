rule TTP_XOR_WriteProcessMemory_350e {
  strings:
    $key_350e = { 62 7c [2] 50 5e [2] 56 6b [2] 78 6b [2] 47 77 }

  condition:
    any of them
}