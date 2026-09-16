rule TTP_XOR_WriteProcessMemory_2b6b {
  strings:
    $key_2b6b = { 7c 19 [2] 4e 3b [2] 48 0e [2] 66 0e [2] 59 12 }

  condition:
    any of them
}