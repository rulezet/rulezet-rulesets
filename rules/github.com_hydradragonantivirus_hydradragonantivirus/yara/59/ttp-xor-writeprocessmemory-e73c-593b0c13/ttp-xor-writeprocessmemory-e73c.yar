rule TTP_XOR_WriteProcessMemory_e73c {
  strings:
    $key_e73c = { b0 4e [2] 82 6c [2] 84 59 [2] aa 59 [2] 95 45 }

  condition:
    any of them
}