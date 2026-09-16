rule TTP_XOR_WriteProcessMemory_c05b {
  strings:
    $key_c05b = { 97 29 [2] a5 0b [2] a3 3e [2] 8d 3e [2] b2 22 }

  condition:
    any of them
}