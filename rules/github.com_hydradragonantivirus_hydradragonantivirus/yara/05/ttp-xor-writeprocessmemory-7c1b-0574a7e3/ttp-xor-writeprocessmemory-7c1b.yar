rule TTP_XOR_WriteProcessMemory_7c1b {
  strings:
    $key_7c1b = { 2b 69 [2] 19 4b [2] 1f 7e [2] 31 7e [2] 0e 62 }

  condition:
    any of them
}