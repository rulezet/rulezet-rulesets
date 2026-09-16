rule TTP_XOR_WriteProcessMemory_761b {
  strings:
    $key_761b = { 21 69 [2] 13 4b [2] 15 7e [2] 3b 7e [2] 04 62 }

  condition:
    any of them
}