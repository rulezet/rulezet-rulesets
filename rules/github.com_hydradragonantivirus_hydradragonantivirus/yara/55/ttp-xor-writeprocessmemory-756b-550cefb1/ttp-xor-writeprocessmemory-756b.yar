rule TTP_XOR_WriteProcessMemory_756b {
  strings:
    $key_756b = { 22 19 [2] 10 3b [2] 16 0e [2] 38 0e [2] 07 12 }

  condition:
    any of them
}