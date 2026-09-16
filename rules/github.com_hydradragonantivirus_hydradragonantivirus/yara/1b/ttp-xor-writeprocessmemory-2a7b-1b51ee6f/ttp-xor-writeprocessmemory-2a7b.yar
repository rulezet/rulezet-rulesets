rule TTP_XOR_WriteProcessMemory_2a7b {
  strings:
    $key_2a7b = { 7d 09 [2] 4f 2b [2] 49 1e [2] 67 1e [2] 58 02 }

  condition:
    any of them
}