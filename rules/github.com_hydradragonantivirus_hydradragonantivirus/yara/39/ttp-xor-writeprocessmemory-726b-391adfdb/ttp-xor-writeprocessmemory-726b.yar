rule TTP_XOR_WriteProcessMemory_726b {
  strings:
    $key_726b = { 25 19 [2] 17 3b [2] 11 0e [2] 3f 0e [2] 00 12 }

  condition:
    any of them
}