rule TTP_XOR_WriteProcessMemory_2cfb {
  strings:
    $key_2cfb = { 7b 89 [2] 49 ab [2] 4f 9e [2] 61 9e [2] 5e 82 }

  condition:
    any of them
}