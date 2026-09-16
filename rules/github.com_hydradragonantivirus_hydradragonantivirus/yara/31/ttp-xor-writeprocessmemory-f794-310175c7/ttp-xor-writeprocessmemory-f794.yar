rule TTP_XOR_WriteProcessMemory_f794 {
  strings:
    $key_f794 = { a0 e6 [2] 92 c4 [2] 94 f1 [2] ba f1 [2] 85 ed }

  condition:
    any of them
}