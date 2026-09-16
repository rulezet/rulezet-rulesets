rule TTP_XOR_WriteProcessMemory_c767 {
  strings:
    $key_c767 = { 90 15 [2] a2 37 [2] a4 02 [2] 8a 02 [2] b5 1e }

  condition:
    any of them
}