rule TTP_XOR_WriteProcessMemory_280b {
  strings:
    $key_280b = { 7f 79 [2] 4d 5b [2] 4b 6e [2] 65 6e [2] 5a 72 }

  condition:
    any of them
}