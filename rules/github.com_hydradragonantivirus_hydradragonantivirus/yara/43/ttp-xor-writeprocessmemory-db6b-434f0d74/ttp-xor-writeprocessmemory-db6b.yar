rule TTP_XOR_WriteProcessMemory_db6b {
  strings:
    $key_db6b = { 8c 19 [2] be 3b [2] b8 0e [2] 96 0e [2] a9 12 }

  condition:
    any of them
}