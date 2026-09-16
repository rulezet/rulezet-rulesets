rule TTP_XOR_WriteProcessMemory_501b {
  strings:
    $key_501b = { 07 69 [2] 35 4b [2] 33 7e [2] 1d 7e [2] 22 62 }

  condition:
    any of them
}