rule TTP_XOR_WriteProcessMemory_e71b {
  strings:
    $key_e71b = { b0 69 [2] 82 4b [2] 84 7e [2] aa 7e [2] 95 62 }

  condition:
    any of them
}