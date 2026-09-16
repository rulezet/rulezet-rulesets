rule TTP_XOR_WriteProcessMemory_222e {
  strings:
    $key_222e = { 75 5c [2] 47 7e [2] 41 4b [2] 6f 4b [2] 50 57 }

  condition:
    any of them
}