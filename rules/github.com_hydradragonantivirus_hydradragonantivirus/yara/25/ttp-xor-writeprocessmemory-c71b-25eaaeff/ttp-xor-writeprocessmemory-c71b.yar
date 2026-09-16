rule TTP_XOR_WriteProcessMemory_c71b {
  strings:
    $key_c71b = { 90 69 [2] a2 4b [2] a4 7e [2] 8a 7e [2] b5 62 }

  condition:
    any of them
}