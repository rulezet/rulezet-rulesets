rule TTP_XOR_WriteProcessMemory_121b {
  strings:
    $key_121b = { 45 69 [2] 77 4b [2] 71 7e [2] 5f 7e [2] 60 62 }

  condition:
    any of them
}