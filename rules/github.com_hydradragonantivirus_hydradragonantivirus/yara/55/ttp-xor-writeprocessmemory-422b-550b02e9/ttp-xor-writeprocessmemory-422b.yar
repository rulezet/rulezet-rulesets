rule TTP_XOR_WriteProcessMemory_422b {
  strings:
    $key_422b = { 15 59 [2] 27 7b [2] 21 4e [2] 0f 4e [2] 30 52 }

  condition:
    any of them
}