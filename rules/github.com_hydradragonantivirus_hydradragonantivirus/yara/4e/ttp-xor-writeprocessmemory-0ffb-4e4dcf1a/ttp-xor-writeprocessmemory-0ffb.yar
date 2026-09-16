rule TTP_XOR_WriteProcessMemory_0ffb {
  strings:
    $key_0ffb = { 58 89 [2] 6a ab [2] 6c 9e [2] 42 9e [2] 7d 82 }

  condition:
    any of them
}