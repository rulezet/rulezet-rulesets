rule TTP_XOR_WriteProcessMemory_111b {
  strings:
    $key_111b = { 46 69 [2] 74 4b [2] 72 7e [2] 5c 7e [2] 63 62 }

  condition:
    any of them
}