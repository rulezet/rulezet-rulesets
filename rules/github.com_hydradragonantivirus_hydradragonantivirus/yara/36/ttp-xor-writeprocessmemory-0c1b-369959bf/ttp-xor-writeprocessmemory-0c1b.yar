rule TTP_XOR_WriteProcessMemory_0c1b {
  strings:
    $key_0c1b = { 5b 69 [2] 69 4b [2] 6f 7e [2] 41 7e [2] 7e 62 }

  condition:
    any of them
}