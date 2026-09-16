rule TTP_XOR_WriteProcessMemory_170e {
  strings:
    $key_170e = { 40 7c [2] 72 5e [2] 74 6b [2] 5a 6b [2] 65 77 }

  condition:
    any of them
}