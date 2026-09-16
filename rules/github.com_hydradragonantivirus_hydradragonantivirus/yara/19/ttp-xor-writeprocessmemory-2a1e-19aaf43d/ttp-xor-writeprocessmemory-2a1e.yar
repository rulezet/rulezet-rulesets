rule TTP_XOR_WriteProcessMemory_2a1e {
  strings:
    $key_2a1e = { 7d 6c [2] 4f 4e [2] 49 7b [2] 67 7b [2] 58 67 }

  condition:
    any of them
}