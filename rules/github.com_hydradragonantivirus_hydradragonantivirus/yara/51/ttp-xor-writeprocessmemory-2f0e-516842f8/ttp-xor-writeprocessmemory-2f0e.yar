rule TTP_XOR_WriteProcessMemory_2f0e {
  strings:
    $key_2f0e = { 78 7c [2] 4a 5e [2] 4c 6b [2] 62 6b [2] 5d 77 }

  condition:
    any of them
}