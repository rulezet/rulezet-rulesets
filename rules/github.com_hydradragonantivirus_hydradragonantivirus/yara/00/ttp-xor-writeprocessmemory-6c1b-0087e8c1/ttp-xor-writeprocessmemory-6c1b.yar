rule TTP_XOR_WriteProcessMemory_6c1b {
  strings:
    $key_6c1b = { 3b 69 [2] 09 4b [2] 0f 7e [2] 21 7e [2] 1e 62 }

  condition:
    any of them
}