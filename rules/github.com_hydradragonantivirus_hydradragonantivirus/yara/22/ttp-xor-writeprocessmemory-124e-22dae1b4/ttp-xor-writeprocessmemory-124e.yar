rule TTP_XOR_WriteProcessMemory_124e {
  strings:
    $key_124e = { 45 3c [2] 77 1e [2] 71 2b [2] 5f 2b [2] 60 37 }

  condition:
    any of them
}