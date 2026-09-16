rule TTP_XOR_WriteProcessMemory_352e {
  strings:
    $key_352e = { 62 5c [2] 50 7e [2] 56 4b [2] 78 4b [2] 47 57 }

  condition:
    any of them
}