rule TTP_XOR_WriteProcessMemory_d76b {
  strings:
    $key_d76b = { 80 19 [2] b2 3b [2] b4 0e [2] 9a 0e [2] a5 12 }

  condition:
    any of them
}