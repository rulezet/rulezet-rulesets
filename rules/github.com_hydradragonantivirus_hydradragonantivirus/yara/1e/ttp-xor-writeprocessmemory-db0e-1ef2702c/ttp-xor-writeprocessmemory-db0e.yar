rule TTP_XOR_WriteProcessMemory_db0e {
  strings:
    $key_db0e = { 8c 7c [2] be 5e [2] b8 6b [2] 96 6b [2] a9 77 }

  condition:
    any of them
}