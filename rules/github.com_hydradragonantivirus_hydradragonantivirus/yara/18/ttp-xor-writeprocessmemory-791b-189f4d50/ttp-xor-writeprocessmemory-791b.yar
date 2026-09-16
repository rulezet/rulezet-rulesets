rule TTP_XOR_WriteProcessMemory_791b {
  strings:
    $key_791b = { 2e 69 [2] 1c 4b [2] 1a 7e [2] 34 7e [2] 0b 62 }

  condition:
    any of them
}