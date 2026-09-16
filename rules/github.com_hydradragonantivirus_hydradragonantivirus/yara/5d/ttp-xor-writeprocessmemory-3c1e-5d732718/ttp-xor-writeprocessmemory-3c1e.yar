rule TTP_XOR_WriteProcessMemory_3c1e {
  strings:
    $key_3c1e = { 6b 6c [2] 59 4e [2] 5f 7b [2] 71 7b [2] 4e 67 }

  condition:
    any of them
}