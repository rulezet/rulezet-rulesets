rule TTP_XOR_WriteProcessMemory_a72b {
  strings:
    $key_a72b = { f0 59 [2] c2 7b [2] c4 4e [2] ea 4e [2] d5 52 }

  condition:
    any of them
}