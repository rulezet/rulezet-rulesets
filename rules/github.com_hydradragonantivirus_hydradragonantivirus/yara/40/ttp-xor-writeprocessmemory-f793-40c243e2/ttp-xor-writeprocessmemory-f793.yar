rule TTP_XOR_WriteProcessMemory_f793 {
  strings:
    $key_f793 = { a0 e1 [2] 92 c3 [2] 94 f6 [2] ba f6 [2] 85 ea }

  condition:
    any of them
}