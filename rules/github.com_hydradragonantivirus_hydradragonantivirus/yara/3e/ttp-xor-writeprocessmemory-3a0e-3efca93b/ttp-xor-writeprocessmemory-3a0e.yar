rule TTP_XOR_WriteProcessMemory_3a0e {
  strings:
    $key_3a0e = { 6d 7c [2] 5f 5e [2] 59 6b [2] 77 6b [2] 48 77 }

  condition:
    any of them
}