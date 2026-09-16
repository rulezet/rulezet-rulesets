rule TTP_XOR_WriteProcessMemory_7d1e {
  strings:
    $key_7d1e = { 2a 6c [2] 18 4e [2] 1e 7b [2] 30 7b [2] 0f 67 }

  condition:
    any of them
}