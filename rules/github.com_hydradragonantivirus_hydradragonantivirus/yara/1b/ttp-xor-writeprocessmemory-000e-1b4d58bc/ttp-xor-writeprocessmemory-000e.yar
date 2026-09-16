rule TTP_XOR_WriteProcessMemory_000e {
  strings:
    $key_000e = { 57 7c [2] 65 5e [2] 63 6b [2] 4d 6b [2] 72 77 }

  condition:
    any of them
}