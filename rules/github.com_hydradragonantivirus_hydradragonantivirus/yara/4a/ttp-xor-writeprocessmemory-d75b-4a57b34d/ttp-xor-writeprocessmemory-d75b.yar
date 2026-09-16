rule TTP_XOR_WriteProcessMemory_d75b {
  strings:
    $key_d75b = { 80 29 [2] b2 0b [2] b4 3e [2] 9a 3e [2] a5 22 }

  condition:
    any of them
}