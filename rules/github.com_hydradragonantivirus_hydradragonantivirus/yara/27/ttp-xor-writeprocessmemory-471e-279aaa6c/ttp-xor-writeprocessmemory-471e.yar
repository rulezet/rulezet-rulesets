rule TTP_XOR_WriteProcessMemory_471e {
  strings:
    $key_471e = { 10 6c [2] 22 4e [2] 24 7b [2] 0a 7b [2] 35 67 }

  condition:
    any of them
}