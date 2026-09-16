rule TTP_XOR_WriteProcessMemory_617b {
  strings:
    $key_617b = { 36 09 [2] 04 2b [2] 02 1e [2] 2c 1e [2] 13 02 }

  condition:
    any of them
}