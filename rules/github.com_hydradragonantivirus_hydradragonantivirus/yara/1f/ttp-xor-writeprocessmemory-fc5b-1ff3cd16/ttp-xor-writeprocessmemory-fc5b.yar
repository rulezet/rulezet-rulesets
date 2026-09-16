rule TTP_XOR_WriteProcessMemory_fc5b {
  strings:
    $key_fc5b = { ab 29 [2] 99 0b [2] 9f 3e [2] b1 3e [2] 8e 22 }

  condition:
    any of them
}