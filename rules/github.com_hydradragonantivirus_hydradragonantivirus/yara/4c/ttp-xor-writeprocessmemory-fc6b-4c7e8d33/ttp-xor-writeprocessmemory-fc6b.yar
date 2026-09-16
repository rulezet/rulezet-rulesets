rule TTP_XOR_WriteProcessMemory_fc6b {
  strings:
    $key_fc6b = { ab 19 [2] 99 3b [2] 9f 0e [2] b1 0e [2] 8e 12 }

  condition:
    any of them
}