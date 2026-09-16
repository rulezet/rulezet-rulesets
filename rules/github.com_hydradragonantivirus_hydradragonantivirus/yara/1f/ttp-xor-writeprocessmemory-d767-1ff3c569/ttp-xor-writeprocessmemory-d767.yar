rule TTP_XOR_WriteProcessMemory_d767 {
  strings:
    $key_d767 = { 80 15 [2] b2 37 [2] b4 02 [2] 9a 02 [2] a5 1e }

  condition:
    any of them
}