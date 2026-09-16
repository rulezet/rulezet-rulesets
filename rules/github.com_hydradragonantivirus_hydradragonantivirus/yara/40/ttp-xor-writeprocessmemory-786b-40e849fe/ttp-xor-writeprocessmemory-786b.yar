rule TTP_XOR_WriteProcessMemory_786b {
  strings:
    $key_786b = { 2f 19 [2] 1d 3b [2] 1b 0e [2] 35 0e [2] 0a 12 }

  condition:
    any of them
}