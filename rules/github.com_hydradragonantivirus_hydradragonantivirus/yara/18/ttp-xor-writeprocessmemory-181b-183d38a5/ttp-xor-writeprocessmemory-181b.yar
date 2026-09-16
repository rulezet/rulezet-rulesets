rule TTP_XOR_WriteProcessMemory_181b {
  strings:
    $key_181b = { 4f 69 [2] 7d 4b [2] 7b 7e [2] 55 7e [2] 6a 62 }

  condition:
    any of them
}