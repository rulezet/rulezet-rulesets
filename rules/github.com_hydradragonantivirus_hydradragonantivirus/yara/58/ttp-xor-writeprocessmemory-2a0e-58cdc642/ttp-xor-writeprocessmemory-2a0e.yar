rule TTP_XOR_WriteProcessMemory_2a0e {
  strings:
    $key_2a0e = { 7d 7c [2] 4f 5e [2] 49 6b [2] 67 6b [2] 58 77 }

  condition:
    any of them
}