rule TTP_XOR_WriteProcessMemory_f2ad {
  strings:
    $key_f2ad = { a5 df [2] 97 fd [2] 91 c8 [2] bf c8 [2] 80 d4 }

  condition:
    any of them
}