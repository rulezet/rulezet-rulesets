rule TTP_XOR_WriteProcessMemory_fc4b {
  strings:
    $key_fc4b = { ab 39 [2] 99 1b [2] 9f 2e [2] b1 2e [2] 8e 32 }

  condition:
    any of them
}