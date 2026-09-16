rule TTP_XOR_WriteProcessMemory_523e {
  strings:
    $key_523e = { 05 4c [2] 37 6e [2] 31 5b [2] 1f 5b [2] 20 47 }

  condition:
    any of them
}