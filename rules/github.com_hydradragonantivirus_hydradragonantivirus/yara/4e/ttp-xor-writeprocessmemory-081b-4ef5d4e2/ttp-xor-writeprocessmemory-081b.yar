rule TTP_XOR_WriteProcessMemory_081b {
  strings:
    $key_081b = { 5f 69 [2] 6d 4b [2] 6b 7e [2] 45 7e [2] 7a 62 }

  condition:
    any of them
}