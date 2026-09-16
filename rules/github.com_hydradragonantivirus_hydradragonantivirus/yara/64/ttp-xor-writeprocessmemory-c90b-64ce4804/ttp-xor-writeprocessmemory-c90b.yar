rule TTP_XOR_WriteProcessMemory_c90b {
  strings:
    $key_c90b = { 9e 79 [2] ac 5b [2] aa 6e [2] 84 6e [2] bb 72 }

  condition:
    any of them
}