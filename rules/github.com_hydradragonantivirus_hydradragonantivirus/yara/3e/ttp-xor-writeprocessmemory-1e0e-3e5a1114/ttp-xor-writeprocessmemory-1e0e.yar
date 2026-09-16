rule TTP_XOR_WriteProcessMemory_1e0e {
  strings:
    $key_1e0e = { 49 7c [2] 7b 5e [2] 7d 6b [2] 53 6b [2] 6c 77 }

  condition:
    any of them
}