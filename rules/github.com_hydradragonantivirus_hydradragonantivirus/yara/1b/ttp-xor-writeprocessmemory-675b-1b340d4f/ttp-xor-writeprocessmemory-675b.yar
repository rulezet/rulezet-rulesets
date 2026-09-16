rule TTP_XOR_WriteProcessMemory_675b {
  strings:
    $key_675b = { 30 29 [2] 02 0b [2] 04 3e [2] 2a 3e [2] 15 22 }

  condition:
    any of them
}