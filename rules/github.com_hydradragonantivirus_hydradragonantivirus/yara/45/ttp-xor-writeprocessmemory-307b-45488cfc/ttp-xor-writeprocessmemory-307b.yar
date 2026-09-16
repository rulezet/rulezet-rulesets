rule TTP_XOR_WriteProcessMemory_307b {
  strings:
    $key_307b = { 67 09 [2] 55 2b [2] 53 1e [2] 7d 1e [2] 42 02 }

  condition:
    any of them
}