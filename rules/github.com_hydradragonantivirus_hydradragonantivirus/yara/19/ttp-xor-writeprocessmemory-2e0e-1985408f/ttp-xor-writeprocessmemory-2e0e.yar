rule TTP_XOR_WriteProcessMemory_2e0e {
  strings:
    $key_2e0e = { 79 7c [2] 4b 5e [2] 4d 6b [2] 63 6b [2] 5c 77 }

  condition:
    any of them
}