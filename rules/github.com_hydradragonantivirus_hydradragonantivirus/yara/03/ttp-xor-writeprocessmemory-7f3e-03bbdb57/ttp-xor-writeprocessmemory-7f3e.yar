rule TTP_XOR_WriteProcessMemory_7f3e {
  strings:
    $key_7f3e = { 28 4c [2] 1a 6e [2] 1c 5b [2] 32 5b [2] 0d 47 }

  condition:
    any of them
}