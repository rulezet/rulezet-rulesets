rule TTP_XOR_WriteProcessMemory_f759 {
  strings:
    $key_f759 = { a0 2b [2] 92 09 [2] 94 3c [2] ba 3c [2] 85 20 }

  condition:
    any of them
}