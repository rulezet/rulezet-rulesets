rule TTP_XOR_WriteProcessMemory_0f0e {
  strings:
    $key_0f0e = { 58 7c [2] 6a 5e [2] 6c 6b [2] 42 6b [2] 7d 77 }

  condition:
    any of them
}