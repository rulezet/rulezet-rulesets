rule TTP_XOR_WriteProcessMemory_6f3e {
  strings:
    $key_6f3e = { 38 4c [2] 0a 6e [2] 0c 5b [2] 22 5b [2] 1d 47 }

  condition:
    any of them
}