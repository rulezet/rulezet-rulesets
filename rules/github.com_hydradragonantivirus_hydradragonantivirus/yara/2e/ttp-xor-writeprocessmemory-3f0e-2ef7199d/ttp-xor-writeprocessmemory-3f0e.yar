rule TTP_XOR_WriteProcessMemory_3f0e {
  strings:
    $key_3f0e = { 68 7c [2] 5a 5e [2] 5c 6b [2] 72 6b [2] 4d 77 }

  condition:
    any of them
}