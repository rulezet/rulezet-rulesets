rule TTP_XOR_WriteProcessMemory_f52b {
  strings:
    $key_f52b = { a2 59 [2] 90 7b [2] 96 4e [2] b8 4e [2] 87 52 }

  condition:
    any of them
}