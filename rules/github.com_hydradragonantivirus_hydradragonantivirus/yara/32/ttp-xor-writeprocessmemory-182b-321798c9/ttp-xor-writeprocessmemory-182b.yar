rule TTP_XOR_WriteProcessMemory_182b {
  strings:
    $key_182b = { 4f 59 [2] 7d 7b [2] 7b 4e [2] 55 4e [2] 6a 52 }

  condition:
    any of them
}