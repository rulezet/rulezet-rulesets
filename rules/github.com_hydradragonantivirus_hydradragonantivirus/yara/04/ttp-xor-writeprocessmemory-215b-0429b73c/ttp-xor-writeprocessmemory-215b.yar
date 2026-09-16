rule TTP_XOR_WriteProcessMemory_215b {
  strings:
    $key_215b = { 76 29 [2] 44 0b [2] 42 3e [2] 6c 3e [2] 53 22 }

  condition:
    any of them
}