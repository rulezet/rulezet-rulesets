rule TTP_XOR_WriteProcessMemory_010e {
  strings:
    $key_010e = { 56 7c [2] 64 5e [2] 62 6b [2] 4c 6b [2] 73 77 }

  condition:
    any of them
}