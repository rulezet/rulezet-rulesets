rule TTP_XOR_WriteProcessMemory_793e {
  strings:
    $key_793e = { 2e 4c [2] 1c 6e [2] 1a 5b [2] 34 5b [2] 0b 47 }

  condition:
    any of them
}