rule TTP_XOR_WriteProcessMemory_387b {
  strings:
    $key_387b = { 6f 09 [2] 5d 2b [2] 5b 1e [2] 75 1e [2] 4a 02 }

  condition:
    any of them
}