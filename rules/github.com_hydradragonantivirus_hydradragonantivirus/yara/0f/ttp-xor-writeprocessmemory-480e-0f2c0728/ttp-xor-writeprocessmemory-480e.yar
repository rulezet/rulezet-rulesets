rule TTP_XOR_WriteProcessMemory_480e {
  strings:
    $key_480e = { 1f 7c [2] 2d 5e [2] 2b 6b [2] 05 6b [2] 3a 77 }

  condition:
    any of them
}