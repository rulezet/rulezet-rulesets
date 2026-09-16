rule TTP_XOR_WriteProcessMemory_0a1b {
  strings:
    $key_0a1b = { 5d 69 [2] 6f 4b [2] 69 7e [2] 47 7e [2] 78 62 }

  condition:
    any of them
}