rule TTP_XOR_WriteProcessMemory_132b {
  strings:
    $key_132b = { 44 59 [2] 76 7b [2] 70 4e [2] 5e 4e [2] 61 52 }

  condition:
    any of them
}