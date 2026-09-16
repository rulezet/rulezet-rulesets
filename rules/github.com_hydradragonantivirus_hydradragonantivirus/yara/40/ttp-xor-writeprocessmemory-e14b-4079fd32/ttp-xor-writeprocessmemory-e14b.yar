rule TTP_XOR_WriteProcessMemory_e14b {
  strings:
    $key_e14b = { b6 39 [2] 84 1b [2] 82 2e [2] ac 2e [2] 93 32 }

  condition:
    any of them
}