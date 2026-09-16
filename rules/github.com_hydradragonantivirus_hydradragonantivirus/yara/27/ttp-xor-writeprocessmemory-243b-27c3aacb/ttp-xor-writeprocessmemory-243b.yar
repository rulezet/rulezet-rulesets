rule TTP_XOR_WriteProcessMemory_243b {
  strings:
    $key_243b = { 73 49 [2] 41 6b [2] 47 5e [2] 69 5e [2] 56 42 }

  condition:
    any of them
}