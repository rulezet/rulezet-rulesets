rule TTP_XOR_WriteProcessMemory_f2e2 {
  strings:
    $key_f2e2 = { a5 90 [2] 97 b2 [2] 91 87 [2] bf 87 [2] 80 9b }

  condition:
    any of them
}