rule TTP_XOR_WriteProcessMemory_684b {
  strings:
    $key_684b = { 3f 39 [2] 0d 1b [2] 0b 2e [2] 25 2e [2] 1a 32 }

  condition:
    any of them
}