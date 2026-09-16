rule TTP_XOR_WriteProcessMemory_c97b {
  strings:
    $key_c97b = { 9e 09 [2] ac 2b [2] aa 1e [2] 84 1e [2] bb 02 }

  condition:
    any of them
}