rule TTP_XOR_WriteProcessMemory_fef5 {
  strings:
    $key_fef5 = { a9 87 [2] 9b a5 [2] 9d 90 [2] b3 90 [2] 8c 8c }

  condition:
    any of them
}