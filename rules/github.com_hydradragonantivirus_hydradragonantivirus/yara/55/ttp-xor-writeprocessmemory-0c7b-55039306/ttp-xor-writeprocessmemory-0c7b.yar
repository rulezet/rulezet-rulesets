rule TTP_XOR_WriteProcessMemory_0c7b {
  strings:
    $key_0c7b = { 5b 09 [2] 69 2b [2] 6f 1e [2] 41 1e [2] 7e 02 }

  condition:
    any of them
}