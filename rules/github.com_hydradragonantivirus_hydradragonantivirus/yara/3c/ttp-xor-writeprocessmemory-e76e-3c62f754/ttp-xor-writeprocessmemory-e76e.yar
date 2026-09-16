rule TTP_XOR_WriteProcessMemory_e76e {
  strings:
    $key_e76e = { b0 1c [2] 82 3e [2] 84 0b [2] aa 0b [2] 95 17 }

  condition:
    any of them
}