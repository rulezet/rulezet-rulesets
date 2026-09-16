rule TTP_XOR_WriteProcessMemory_3a3e {
  strings:
    $key_3a3e = { 6d 4c [2] 5f 6e [2] 59 5b [2] 77 5b [2] 48 47 }

  condition:
    any of them
}