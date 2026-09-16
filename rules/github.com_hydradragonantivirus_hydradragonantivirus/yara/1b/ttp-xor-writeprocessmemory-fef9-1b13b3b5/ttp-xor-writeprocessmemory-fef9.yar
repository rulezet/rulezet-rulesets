rule TTP_XOR_WriteProcessMemory_fef9 {
  strings:
    $key_fef9 = { a9 8b [2] 9b a9 [2] 9d 9c [2] b3 9c [2] 8c 80 }

  condition:
    any of them
}