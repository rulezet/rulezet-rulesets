rule TTP_XOR_WriteProcessMemory_167b {
  strings:
    $key_167b = { 41 09 [2] 73 2b [2] 75 1e [2] 5b 1e [2] 64 02 }

  condition:
    any of them
}