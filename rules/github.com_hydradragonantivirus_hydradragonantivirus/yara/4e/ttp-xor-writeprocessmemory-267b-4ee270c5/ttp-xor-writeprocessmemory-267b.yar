rule TTP_XOR_WriteProcessMemory_267b {
  strings:
    $key_267b = { 71 09 [2] 43 2b [2] 45 1e [2] 6b 1e [2] 54 02 }

  condition:
    any of them
}