rule TTP_XOR_WriteProcessMemory_d31b {
  strings:
    $key_d31b = { 84 69 [2] b6 4b [2] b0 7e [2] 9e 7e [2] a1 62 }

  condition:
    any of them
}