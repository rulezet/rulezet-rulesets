rule TTP_XOR_WriteProcessMemory_0d0b {
  strings:
    $key_0d0b = { 5a 79 [2] 68 5b [2] 6e 6e [2] 40 6e [2] 7f 72 }

  condition:
    any of them
}