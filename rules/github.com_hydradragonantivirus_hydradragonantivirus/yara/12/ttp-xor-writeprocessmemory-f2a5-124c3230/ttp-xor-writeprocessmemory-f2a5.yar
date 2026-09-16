rule TTP_XOR_WriteProcessMemory_f2a5 {
  strings:
    $key_f2a5 = { a5 d7 [2] 97 f5 [2] 91 c0 [2] bf c0 [2] 80 dc }

  condition:
    any of them
}