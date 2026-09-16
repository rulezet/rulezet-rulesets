rule TTP_XOR_WriteProcessMemory_6c0e {
  strings:
    $key_6c0e = { 3b 7c [2] 09 5e [2] 0f 6b [2] 21 6b [2] 1e 77 }

  condition:
    any of them
}