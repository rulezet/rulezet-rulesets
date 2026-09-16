rule TTP_XOR_WriteProcessMemory_5dfb {
  strings:
    $key_5dfb = { 0a 89 [2] 38 ab [2] 3e 9e [2] 10 9e [2] 2f 82 }

  condition:
    any of them
}