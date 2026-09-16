rule TTP_XOR_WriteProcessMemory_141e {
  strings:
    $key_141e = { 43 6c [2] 71 4e [2] 77 7b [2] 59 7b [2] 66 67 }

  condition:
    any of them
}