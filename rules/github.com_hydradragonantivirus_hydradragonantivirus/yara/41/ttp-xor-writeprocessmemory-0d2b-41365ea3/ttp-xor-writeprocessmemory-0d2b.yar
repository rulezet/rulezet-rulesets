rule TTP_XOR_WriteProcessMemory_0d2b {
  strings:
    $key_0d2b = { 5a 59 [2] 68 7b [2] 6e 4e [2] 40 4e [2] 7f 52 }

  condition:
    any of them
}