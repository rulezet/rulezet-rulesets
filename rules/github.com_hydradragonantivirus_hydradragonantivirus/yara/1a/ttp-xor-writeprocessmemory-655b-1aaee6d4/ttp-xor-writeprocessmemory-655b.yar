rule TTP_XOR_WriteProcessMemory_655b {
  strings:
    $key_655b = { 32 29 [2] 00 0b [2] 06 3e [2] 28 3e [2] 17 22 }

  condition:
    any of them
}