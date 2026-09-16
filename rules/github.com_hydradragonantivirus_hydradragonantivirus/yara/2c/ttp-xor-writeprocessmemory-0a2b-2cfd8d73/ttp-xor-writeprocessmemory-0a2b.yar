rule TTP_XOR_WriteProcessMemory_0a2b {
  strings:
    $key_0a2b = { 5d 59 [2] 6f 7b [2] 69 4e [2] 47 4e [2] 78 52 }

  condition:
    any of them
}