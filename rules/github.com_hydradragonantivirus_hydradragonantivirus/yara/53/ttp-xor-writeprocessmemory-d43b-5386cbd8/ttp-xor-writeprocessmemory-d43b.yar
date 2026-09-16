rule TTP_XOR_WriteProcessMemory_d43b {
  strings:
    $key_d43b = { 83 49 [2] b1 6b [2] b7 5e [2] 99 5e [2] a6 42 }

  condition:
    any of them
}