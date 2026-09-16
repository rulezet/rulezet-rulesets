rule TTP_XOR_WriteProcessMemory_3b2b {
  strings:
    $key_3b2b = { 6c 59 [2] 5e 7b [2] 58 4e [2] 76 4e [2] 49 52 }

  condition:
    any of them
}