rule TTP_XOR_WriteProcessMemory_172b {
  strings:
    $key_172b = { 40 59 [2] 72 7b [2] 74 4e [2] 5a 4e [2] 65 52 }

  condition:
    any of them
}