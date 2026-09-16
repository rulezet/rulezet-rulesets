rule TTP_XOR_WriteProcessMemory_4e0e {
  strings:
    $key_4e0e = { 19 7c [2] 2b 5e [2] 2d 6b [2] 03 6b [2] 3c 77 }

  condition:
    any of them
}