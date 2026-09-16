rule TTP_XOR_WriteProcessMemory_f2ae {
  strings:
    $key_f2ae = { a5 dc [2] 97 fe [2] 91 cb [2] bf cb [2] 80 d7 }

  condition:
    any of them
}