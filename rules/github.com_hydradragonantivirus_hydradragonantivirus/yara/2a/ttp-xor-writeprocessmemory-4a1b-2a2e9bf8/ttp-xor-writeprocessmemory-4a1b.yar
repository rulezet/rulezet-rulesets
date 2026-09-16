rule TTP_XOR_WriteProcessMemory_4a1b {
  strings:
    $key_4a1b = { 1d 69 [2] 2f 4b [2] 29 7e [2] 07 7e [2] 38 62 }

  condition:
    any of them
}