rule TTP_XOR_WriteProcessMemory_d41b {
  strings:
    $key_d41b = { 83 69 [2] b1 4b [2] b7 7e [2] 99 7e [2] a6 62 }

  condition:
    any of them
}