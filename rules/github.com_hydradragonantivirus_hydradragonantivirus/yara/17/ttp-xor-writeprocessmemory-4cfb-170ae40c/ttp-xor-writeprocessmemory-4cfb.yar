rule TTP_XOR_WriteProcessMemory_4cfb {
  strings:
    $key_4cfb = { 1b 89 [2] 29 ab [2] 2f 9e [2] 01 9e [2] 3e 82 }

  condition:
    any of them
}