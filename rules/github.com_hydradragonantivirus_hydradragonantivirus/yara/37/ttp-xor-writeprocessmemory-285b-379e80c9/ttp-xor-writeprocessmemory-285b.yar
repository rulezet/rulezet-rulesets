rule TTP_XOR_WriteProcessMemory_285b {
  strings:
    $key_285b = { 7f 29 [2] 4d 0b [2] 4b 3e [2] 65 3e [2] 5a 22 }

  condition:
    any of them
}