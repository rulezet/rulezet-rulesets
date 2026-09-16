rule TTP_XOR_WriteProcessMemory_383b {
  strings:
    $key_383b = { 6f 49 [2] 5d 6b [2] 5b 5e [2] 75 5e [2] 4a 42 }

  condition:
    any of them
}