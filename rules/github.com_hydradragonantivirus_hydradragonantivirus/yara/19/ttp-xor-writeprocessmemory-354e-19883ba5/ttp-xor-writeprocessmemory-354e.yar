rule TTP_XOR_WriteProcessMemory_354e {
  strings:
    $key_354e = { 62 3c [2] 50 1e [2] 56 2b [2] 78 2b [2] 47 37 }

  condition:
    any of them
}