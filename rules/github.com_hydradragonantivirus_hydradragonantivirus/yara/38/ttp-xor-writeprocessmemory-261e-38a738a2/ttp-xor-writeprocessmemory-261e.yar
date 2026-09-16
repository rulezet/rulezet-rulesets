rule TTP_XOR_WriteProcessMemory_261e {
  strings:
    $key_261e = { 71 6c [2] 43 4e [2] 45 7b [2] 6b 7b [2] 54 67 }

  condition:
    any of them
}