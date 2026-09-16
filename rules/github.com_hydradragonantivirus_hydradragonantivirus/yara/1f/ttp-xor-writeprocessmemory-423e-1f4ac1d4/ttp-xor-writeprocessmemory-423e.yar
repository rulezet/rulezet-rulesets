rule TTP_XOR_WriteProcessMemory_423e {
  strings:
    $key_423e = { 15 4c [2] 27 6e [2] 21 5b [2] 0f 5b [2] 30 47 }

  condition:
    any of them
}