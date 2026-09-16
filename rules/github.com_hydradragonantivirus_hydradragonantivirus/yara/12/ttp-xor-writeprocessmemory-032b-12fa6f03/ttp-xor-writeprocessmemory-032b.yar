rule TTP_XOR_WriteProcessMemory_032b {
  strings:
    $key_032b = { 54 59 [2] 66 7b [2] 60 4e [2] 4e 4e [2] 71 52 }

  condition:
    any of them
}