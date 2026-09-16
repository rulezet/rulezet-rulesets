rule TTP_XOR_WriteProcessMemory_122b {
  strings:
    $key_122b = { 45 59 [2] 77 7b [2] 71 4e [2] 5f 4e [2] 60 52 }

  condition:
    any of them
}