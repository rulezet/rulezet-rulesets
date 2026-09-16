rule TTP_XOR_WriteProcessMemory_f2d9 {
  strings:
    $key_f2d9 = { a5 ab [2] 97 89 [2] 91 bc [2] bf bc [2] 80 a0 }

  condition:
    any of them
}