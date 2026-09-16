rule TTP_XOR_WriteProcessMemory_126b {
  strings:
    $key_126b = { 45 19 [2] 77 3b [2] 71 0e [2] 5f 0e [2] 60 12 }

  condition:
    any of them
}