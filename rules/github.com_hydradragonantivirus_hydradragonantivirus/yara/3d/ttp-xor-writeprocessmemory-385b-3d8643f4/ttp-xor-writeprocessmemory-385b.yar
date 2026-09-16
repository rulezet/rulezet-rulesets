rule TTP_XOR_WriteProcessMemory_385b {
  strings:
    $key_385b = { 6f 29 [2] 5d 0b [2] 5b 3e [2] 75 3e [2] 4a 22 }

  condition:
    any of them
}