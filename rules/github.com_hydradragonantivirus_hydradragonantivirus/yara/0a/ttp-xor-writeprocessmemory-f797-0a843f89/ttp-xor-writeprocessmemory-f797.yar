rule TTP_XOR_WriteProcessMemory_f797 {
  strings:
    $key_f797 = { a0 e5 [2] 92 c7 [2] 94 f2 [2] ba f2 [2] 85 ee }

  condition:
    any of them
}