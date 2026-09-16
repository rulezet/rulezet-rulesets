rule TTP_XOR_WriteProcessMemory_222b {
  strings:
    $key_222b = { 75 59 [2] 47 7b [2] 41 4e [2] 6f 4e [2] 50 52 }

  condition:
    any of them
}