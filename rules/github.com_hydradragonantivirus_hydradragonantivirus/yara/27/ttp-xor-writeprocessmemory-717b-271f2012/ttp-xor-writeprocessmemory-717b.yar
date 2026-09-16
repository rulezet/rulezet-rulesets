rule TTP_XOR_WriteProcessMemory_717b {
  strings:
    $key_717b = { 26 09 [2] 14 2b [2] 12 1e [2] 3c 1e [2] 03 02 }

  condition:
    any of them
}