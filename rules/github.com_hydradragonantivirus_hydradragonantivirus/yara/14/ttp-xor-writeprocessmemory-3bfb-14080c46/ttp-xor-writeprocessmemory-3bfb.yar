rule TTP_XOR_WriteProcessMemory_3bfb {
  strings:
    $key_3bfb = { 6c 89 [2] 5e ab [2] 58 9e [2] 76 9e [2] 49 82 }

  condition:
    any of them
}