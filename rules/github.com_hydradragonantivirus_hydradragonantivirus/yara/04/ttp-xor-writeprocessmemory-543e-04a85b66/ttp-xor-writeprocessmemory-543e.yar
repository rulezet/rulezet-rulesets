rule TTP_XOR_WriteProcessMemory_543e {
  strings:
    $key_543e = { 03 4c [2] 31 6e [2] 37 5b [2] 19 5b [2] 26 47 }

  condition:
    any of them
}