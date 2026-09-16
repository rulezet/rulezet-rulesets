rule TTP_XOR_WriteProcessMemory_0cfb {
  strings:
    $key_0cfb = { 5b 89 [2] 69 ab [2] 6f 9e [2] 41 9e [2] 7e 82 }

  condition:
    any of them
}