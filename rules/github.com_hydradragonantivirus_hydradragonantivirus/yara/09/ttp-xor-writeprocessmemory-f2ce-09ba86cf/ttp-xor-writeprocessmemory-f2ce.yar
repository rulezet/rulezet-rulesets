rule TTP_XOR_WriteProcessMemory_f2ce {
  strings:
    $key_f2ce = { a5 bc [2] 97 9e [2] 91 ab [2] bf ab [2] 80 b7 }

  condition:
    any of them
}