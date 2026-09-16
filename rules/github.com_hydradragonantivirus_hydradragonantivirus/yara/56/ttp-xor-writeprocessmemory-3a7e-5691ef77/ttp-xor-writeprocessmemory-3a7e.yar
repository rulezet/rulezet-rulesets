rule TTP_XOR_WriteProcessMemory_3a7e {
  strings:
    $key_3a7e = { 6d 0c [2] 5f 2e [2] 59 1b [2] 77 1b [2] 48 07 }

  condition:
    any of them
}