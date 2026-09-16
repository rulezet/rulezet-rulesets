rule TTP_XOR_WriteProcessMemory_f5ce {
  strings:
    $key_f5ce = { a2 bc [2] 90 9e [2] 96 ab [2] b8 ab [2] 87 b7 }

  condition:
    any of them
}