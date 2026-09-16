rule TTP_XOR_WriteProcessMemory_732b {
  strings:
    $key_732b = { 24 59 [2] 16 7b [2] 10 4e [2] 3e 4e [2] 01 52 }

  condition:
    any of them
}