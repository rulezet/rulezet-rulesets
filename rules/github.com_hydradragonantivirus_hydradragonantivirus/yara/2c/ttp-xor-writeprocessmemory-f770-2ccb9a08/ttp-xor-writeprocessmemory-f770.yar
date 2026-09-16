rule TTP_XOR_WriteProcessMemory_f770 {
  strings:
    $key_f770 = { a0 02 [2] 92 20 [2] 94 15 [2] ba 15 [2] 85 09 }

  condition:
    any of them
}