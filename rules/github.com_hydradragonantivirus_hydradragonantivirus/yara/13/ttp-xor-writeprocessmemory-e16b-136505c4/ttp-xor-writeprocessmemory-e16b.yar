rule TTP_XOR_WriteProcessMemory_e16b {
  strings:
    $key_e16b = { b6 19 [2] 84 3b [2] 82 0e [2] ac 0e [2] 93 12 }

  condition:
    any of them
}