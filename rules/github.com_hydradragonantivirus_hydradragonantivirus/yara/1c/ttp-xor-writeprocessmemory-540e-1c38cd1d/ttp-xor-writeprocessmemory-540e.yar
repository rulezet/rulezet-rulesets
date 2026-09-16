rule TTP_XOR_WriteProcessMemory_540e {
  strings:
    $key_540e = { 03 7c [2] 31 5e [2] 37 6b [2] 19 6b [2] 26 77 }

  condition:
    any of them
}