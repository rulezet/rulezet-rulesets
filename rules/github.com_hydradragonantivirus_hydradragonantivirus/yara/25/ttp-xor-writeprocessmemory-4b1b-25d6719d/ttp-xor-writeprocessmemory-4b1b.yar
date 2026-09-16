rule TTP_XOR_WriteProcessMemory_4b1b {
  strings:
    $key_4b1b = { 1c 69 [2] 2e 4b [2] 28 7e [2] 06 7e [2] 39 62 }

  condition:
    any of them
}