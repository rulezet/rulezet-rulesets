rule TTP_XOR_WriteProcessMemory_161b {
  strings:
    $key_161b = { 41 69 [2] 73 4b [2] 75 7e [2] 5b 7e [2] 64 62 }

  condition:
    any of them
}