rule TTP_XOR_WriteProcessMemory_3a1e {
  strings:
    $key_3a1e = { 6d 6c [2] 5f 4e [2] 59 7b [2] 77 7b [2] 48 67 }

  condition:
    any of them
}