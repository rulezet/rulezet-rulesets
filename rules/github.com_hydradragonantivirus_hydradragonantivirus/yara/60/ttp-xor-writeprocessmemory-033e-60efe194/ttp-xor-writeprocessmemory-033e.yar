rule TTP_XOR_WriteProcessMemory_033e {
  strings:
    $key_033e = { 54 4c [2] 66 6e [2] 60 5b [2] 4e 5b [2] 71 47 }

  condition:
    any of them
}