rule TTP_XOR_WriteProcessMemory_542b {
  strings:
    $key_542b = { 03 59 [2] 31 7b [2] 37 4e [2] 19 4e [2] 26 52 }

  condition:
    any of them
}