rule TTP_XOR_WriteProcessMemory_520e {
  strings:
    $key_520e = { 05 7c [2] 37 5e [2] 31 6b [2] 1f 6b [2] 20 77 }

  condition:
    any of them
}