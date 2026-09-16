rule TTP_XOR_WriteProcessMemory_2f1e {
  strings:
    $key_2f1e = { 78 6c [2] 4a 4e [2] 4c 7b [2] 62 7b [2] 5d 67 }

  condition:
    any of them
}