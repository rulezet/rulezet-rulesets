rule TTP_XOR_WriteProcessMemory_3cfb {
  strings:
    $key_3cfb = { 6b 89 [2] 59 ab [2] 5f 9e [2] 71 9e [2] 4e 82 }

  condition:
    any of them
}