rule TTP_XOR_WriteProcessMemory_367b {
  strings:
    $key_367b = { 61 09 [2] 53 2b [2] 55 1e [2] 7b 1e [2] 44 02 }

  condition:
    any of them
}