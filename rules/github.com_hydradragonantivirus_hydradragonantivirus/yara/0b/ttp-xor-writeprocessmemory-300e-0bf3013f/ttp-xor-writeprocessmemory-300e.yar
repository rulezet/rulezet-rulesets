rule TTP_XOR_WriteProcessMemory_300e {
  strings:
    $key_300e = { 67 7c [2] 55 5e [2] 53 6b [2] 7d 6b [2] 42 77 }

  condition:
    any of them
}