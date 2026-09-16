rule TTP_XOR_WriteProcessMemory_147b {
  strings:
    $key_147b = { 43 09 [2] 71 2b [2] 77 1e [2] 59 1e [2] 66 02 }

  condition:
    any of them
}