rule TTP_XOR_WriteProcessMemory_d32b {
  strings:
    $key_d32b = { 84 59 [2] b6 7b [2] b0 4e [2] 9e 4e [2] a1 52 }

  condition:
    any of them
}