rule TTP_XOR_WriteProcessMemory_f529 {
  strings:
    $key_f529 = { a2 5b [2] 90 79 [2] 96 4c [2] b8 4c [2] 87 50 }

  condition:
    any of them
}