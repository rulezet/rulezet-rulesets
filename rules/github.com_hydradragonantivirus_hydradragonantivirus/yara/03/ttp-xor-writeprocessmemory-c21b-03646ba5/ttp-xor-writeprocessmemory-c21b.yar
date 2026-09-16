rule TTP_XOR_WriteProcessMemory_c21b {
  strings:
    $key_c21b = { 95 69 [2] a7 4b [2] a1 7e [2] 8f 7e [2] b0 62 }

  condition:
    any of them
}