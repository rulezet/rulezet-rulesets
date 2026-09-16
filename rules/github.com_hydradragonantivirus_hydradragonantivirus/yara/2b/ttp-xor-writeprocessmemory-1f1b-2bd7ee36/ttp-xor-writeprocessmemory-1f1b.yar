rule TTP_XOR_WriteProcessMemory_1f1b {
  strings:
    $key_1f1b = { 48 69 [2] 7a 4b [2] 7c 7e [2] 52 7e [2] 6d 62 }

  condition:
    any of them
}