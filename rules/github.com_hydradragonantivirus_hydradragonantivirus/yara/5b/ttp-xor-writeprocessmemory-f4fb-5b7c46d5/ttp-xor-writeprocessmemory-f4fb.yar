rule TTP_XOR_WriteProcessMemory_f4fb {
  strings:
    $key_f4fb = { a3 89 [2] 91 ab [2] 97 9e [2] b9 9e [2] 86 82 }

  condition:
    any of them
}