rule TTP_XOR_WriteProcessMemory_200e {
  strings:
    $key_200e = { 77 7c [2] 45 5e [2] 43 6b [2] 6d 6b [2] 52 77 }

  condition:
    any of them
}