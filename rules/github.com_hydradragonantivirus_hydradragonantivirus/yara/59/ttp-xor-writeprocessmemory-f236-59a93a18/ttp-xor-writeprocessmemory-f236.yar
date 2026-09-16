rule TTP_XOR_WriteProcessMemory_f236 {
  strings:
    $key_f236 = { a5 44 [2] 97 66 [2] 91 53 [2] bf 53 [2] 80 4f }

  condition:
    any of them
}