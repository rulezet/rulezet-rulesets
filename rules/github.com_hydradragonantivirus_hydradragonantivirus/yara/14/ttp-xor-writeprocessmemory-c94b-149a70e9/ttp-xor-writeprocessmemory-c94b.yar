rule TTP_XOR_WriteProcessMemory_c94b {
  strings:
    $key_c94b = { 9e 39 [2] ac 1b [2] aa 2e [2] 84 2e [2] bb 32 }

  condition:
    any of them
}