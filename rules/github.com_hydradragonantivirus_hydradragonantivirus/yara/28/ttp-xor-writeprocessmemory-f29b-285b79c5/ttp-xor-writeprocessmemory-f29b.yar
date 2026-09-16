rule TTP_XOR_WriteProcessMemory_f29b {
  strings:
    $key_f29b = { a5 e9 [2] 97 cb [2] 91 fe [2] bf fe [2] 80 e2 }

  condition:
    any of them
}