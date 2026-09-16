rule TTP_XOR_WriteProcessMemory_3c0e {
  strings:
    $key_3c0e = { 6b 7c [2] 59 5e [2] 5f 6b [2] 71 6b [2] 4e 77 }

  condition:
    any of them
}