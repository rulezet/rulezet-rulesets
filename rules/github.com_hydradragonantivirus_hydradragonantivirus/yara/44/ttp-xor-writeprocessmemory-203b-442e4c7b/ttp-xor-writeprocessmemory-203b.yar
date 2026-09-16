rule TTP_XOR_WriteProcessMemory_203b {
  strings:
    $key_203b = { 77 49 [2] 45 6b [2] 43 5e [2] 6d 5e [2] 52 42 }

  condition:
    any of them
}