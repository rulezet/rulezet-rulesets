rule TTP_XOR_WriteProcessMemory_143e {
  strings:
    $key_143e = { 43 4c [2] 71 6e [2] 77 5b [2] 59 5b [2] 66 47 }

  condition:
    any of them
}